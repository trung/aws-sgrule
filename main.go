package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var sgRuleChannel = make(chan types.SecurityGroupRule)
var done = make(chan bool)

func main() {
	var sgId string
	var ruleStartsWith string
	var ruleContains string
	var dryRun bool
	flag.StringVar(&sgId, "group-id", "", "Security Group ID")
	flag.StringVar(&ruleStartsWith, "starts-with", "", "Match all rules which have description starting with a string")
	flag.StringVar(&ruleContains, "contains", "", "Match all rules which have description containing a string")
	flag.BoolVar(&dryRun, "dry-run", false, "If true, only output details without actually updating rules")
	flag.Parse()

	if sgId == "" || (ruleStartsWith == "" && ruleContains == "") {
		flag.Usage()
		os.Exit(1)
	}

	publicIP, err := queryPublicIP()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Public IP:", publicIP)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	client := ec2.NewFromConfig(cfg)

	go sgRuleUpdater(dryRun, client, fmt.Sprintf("%s/32", publicIP))

	paginator := ec2.NewDescribeSecurityGroupRulesPaginator(client, &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgId},
			},
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		for _, r := range page.SecurityGroupRules {
			if !aws.ToBool(r.IsEgress) && ((ruleStartsWith != "" && strings.HasPrefix(aws.ToString(r.Description), ruleStartsWith)) ||
				(ruleContains != "" && strings.Contains(aws.ToString(r.Description), ruleContains))) {
				sgRuleChannel <- r
			}
		}
	}
	close(sgRuleChannel)
	<-done
}

func sgRuleUpdater(dryRun bool, client *ec2.Client, newCidrIpv4 string) {
	for r := range sgRuleChannel {
		log.Println("Updating",
			aws.ToString(r.SecurityGroupRuleId),
			aws.ToString(r.IpProtocol),
			aws.ToInt32(r.FromPort),
			aws.ToInt32(r.ToPort),
			aws.ToString(r.CidrIpv4),
			aws.ToString(r.Description))
		if dryRun {
			continue
		}
		// first revoke existing
		_, err := client.RevokeSecurityGroupIngress(context.TODO(), &ec2.RevokeSecurityGroupIngressInput{
			GroupId:              r.GroupId,
			SecurityGroupRuleIds: []string{aws.ToString(r.SecurityGroupRuleId)},
		})
		if err != nil {
			log.Println("ERROR", "Unable to revoke existing rule", aws.ToString(r.SecurityGroupRuleId))
			continue
		}
		log.Println("Revoked", aws.ToString(r.CidrIpv4), "under existing rule", aws.ToString(r.SecurityGroupRuleId))
		// then authorize new rule
		resp, err := client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:    r.GroupId,
			IpProtocol: r.IpProtocol,
			FromPort:   r.FromPort,
			ToPort:     r.ToPort,
			CidrIp:     aws.String(newCidrIpv4),
		})
		if err != nil {
			log.Println("ERROR", "Unable to authorize new rule")
			continue
		}
		newSgRuleId := resp.SecurityGroupRules[0].SecurityGroupRuleId
		log.Println("Authorized", newCidrIpv4, "under new rule", aws.ToString(newSgRuleId))
		// then update description
		_, err = client.UpdateSecurityGroupRuleDescriptionsIngress(context.TODO(), &ec2.UpdateSecurityGroupRuleDescriptionsIngressInput{
			GroupId: r.GroupId,
			SecurityGroupRuleDescriptions: []types.SecurityGroupRuleDescription{
				{
					SecurityGroupRuleId: newSgRuleId,
					Description:         r.Description,
				},
			},
		})
		if err != nil {
			log.Println("ERROR", "Unable to update rule description")
			continue
		}
		log.Println("Updated Description", aws.ToString(newSgRuleId))
	}
	done <- true
}

func queryPublicIP() (string, error) {
	resp, err := http.Get("https://bot.whatismyipaddress.com")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	raw, err := ioutil.ReadAll(resp.Body)

	return string(raw), err
}
