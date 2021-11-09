A utility updates AWS Security Group Rules found by description matching

- Update `cidrIpV4` value with current public IP

```
Usage of aws-sgrule:
  -contains string
        Match all rules which have description containing a string
  -dry-run
        If true, only output details without actually updating rules
  -group-id string
        Security Group ID
  -starts-with string
        Match all rules which have description starting with a string
```

## Install

```
go get -u github.com/trung/aws-sgrule
```

## Example

```
aws-sgrule -group-id sg-12341 -contains Foo
```
