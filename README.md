A utility updates AWS Security Group Rules found by description matching

- Update `cidrIpV4` value with current public IP

```
go get github.com/trung/aws-sgrule
aws-sgrule -group-id sg-12341 -contains Foo
```
