### IAM Identities

AWS account root user
-Created AWS account that has complete access to all AWS services and resources in the account

AWS IAM user
-entity you create in AWS
-IAM User represents a person or service who uses the IAM user to interact with AWS
-When created, you grant IAM users permissions by making it a member of a group that has appropriate permission policies attached (recommended) or by directly 
attaching policies to the user itself
-Can also clone the permissions of an existing IAM user which makes the new user a member of the same groups and attaches all the same policies

AWS IAM group
-Collection of IAM users
-Can use groups to specify permissions for a collection of users which can make those permissions easier to manage
-For example, if a person changes jobs you can just remove them from the old groups instead of editing permissions and add him to the appropriate new group
-A group CANNOT be identified as a Principal in a resource based policy
-When you attach an identity based policy to a group all of the users in the group receive the permissions from the group

AWS IAM Role
-Similar to a user, it is an identity with permission policies that determine what the identity can and cannot do in AWS
-Role does not have any credentials associated with it but instead temporary security credentials for role session
-Role can be assumed by anyone who needs it
-IAM user can assume a role to temporarily take on different permissions for a specific task
-Role can be assigned to a federated user who signs in using an external identity provider instead of IAM
-When using temporary security credentials the call must include a session token 

## AWS Cloudtrail

-Service that enables governance, compliance, operatoinal auditing, and risk auditing of AWS Accounts
-CloudTrail can be used to log, continously monitor, and retain account activity related to actions across an AWS based infrastructure
-TLDR Cloudtrail monitors AWS API calls across nearly every AWS service

## GuardDuty

GuardDuty is a threat detection service that monitors for malicious activity and unauthorized behavior to protect AWS accounts and workloads

## AWS Security Token Service

-AWS STS is a web service that enables you to request temporary limited privilege credentials for IAM users or for federated users

## AWS S3

-S3 has a simple web services interface that you can use to store and retrive any amount of data

Create a bucket

aws s3 mb <target> [--options]

List Bucket

aws s3 ls
aws s3 ls s3://bucket-name

Copy Objects

aws s3 cp s3://bucket-name/example s3://my-bucket/
aws s3 cp filename.txt s3://bucket-name

## Managed and Inline policies

Managed policies

Standalone policy that is creaed and administered by AWS. Standalone policy means that the policy has its own Amazon Resource Name that includes the policy name. 
AWS Managed policies are designed to provide permissions for many common use cases such as AmazonDynameDBFullAccess

Customer Managed policies

You can create standalone policies that you administer in your own AWS account, which we refer to as customer managed policies. You can then attach the policies to multiple principal entities in your AWS account. When you attach a policy to a principal entity you give the entity the permissions that are defined in the policy

Inline policies

An inline policy is a policy thats embedded in an IAM identity. That is the policy is an inherent part of the identity. You can create a policy and embed it in a identity, either when you create the identity or later