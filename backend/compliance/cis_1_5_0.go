package compliance

import (
	"github.com/SecoCloud/SecoCloud/rules/cloudtrail"
	"github.com/SecoCloud/SecoCloud/rules/cloudwatch"
	"github.com/SecoCloud/SecoCloud/rules/ec2"
	"github.com/SecoCloud/SecoCloud/rules/iam"
	"github.com/SecoCloud/SecoCloud/rules/kms"
	"github.com/SecoCloud/SecoCloud/rules/rds"
	"github.com/SecoCloud/SecoCloud/rules/s3"
	"github.com/SecoCloud/SecoCloud/rules/securityhub"
	"github.com/SecoCloud/SecoCloud/rules/types"
	"github.com/SecoCloud/SecoCloud/rules/vpc"
)

var Cis_1_5_0_Spec ComplianceFrameworkSpec = ComplianceFrameworkSpec{
	FrameworkName: "CIS 1.5.0",
	ComplianceControlGroupSpecs: []ComplianceControlGroupSpec{
		{
			GroupName: "1 Identity and Access Management",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName:    "1.1 - Maintain current contact details",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName:    "1.2 - Ensure security contact information is registered",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName:    "1.3 - Ensure security questions are registered in the AWS account",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName: "1.4 - Ensure no 'root' user account access key exists ",
					SecoCloudRules: []types.Rule{
						iam.NoRootAccessKeys{},
					},
				},
				{
					ControlName: "1.5 - Ensure MFA is enabled for the 'root' user account",
					SecoCloudRules: []types.Rule{
						iam.RootMfaEnabled{},
					},
				},
				{
					ControlName:    "1.6 - Ensure hardware MFA is enabled for the 'root' user account",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName: "1.7 - Eliminate use of the 'root' user for administrative and daily tasks",
					SecoCloudRules: []types.Rule{
						iam.RootAccountUsed{},
					},
				},
				{
					ControlName: "1.8 - Ensure IAM password policy requires minimum length of 14 or greater",
					SecoCloudRules: []types.Rule{
						iam.PasswordMinLength{},
					},
				},
				{
					ControlName: "1.9 - Ensure IAM password policy prevents password reuse",
					SecoCloudRules: []types.Rule{
						iam.PasswordReusePrevention{},
					},
				},
				{
					ControlName: "1.10 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
					SecoCloudRules: []types.Rule{
						iam.MfaEnabledForConsoleAccess{},
					},
				},
				{
					ControlName: "1.11 - Do not setup access keys during initial user setup for all IAM users that have a console password",
					SecoCloudRules: []types.Rule{
						iam.AvoidAccessKeysAtSetup{},
					},
				},
				{
					ControlName: "1.12 - Ensure credentials unused for 45 days or greater are disabled",
					SecoCloudRules: []types.Rule{
						iam.CredentialsUnused90Days{},
					},
				},
				{
					ControlName: "1.13 -  Ensure there is only one active access key available for any single IAM user",
					SecoCloudRules: []types.Rule{
						iam.UserActiveAccessKeys{},
					},
				},
				{
					ControlName: "1.14 - Ensure access keys are rotated every 90 days or less",
					SecoCloudRules: []types.Rule{
						iam.AccessKeysRotated90Days{},
					},
				},
				{
					ControlName: "1.15 - Ensure IAM Users Receive Permissions Only Through Groups",
					SecoCloudRules: []types.Rule{
						iam.NoUserPolicies{},
					},
				},
				{
					ControlName: "1.16 - Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached",
					SecoCloudRules: []types.Rule{
						iam.PasswordExpiry{},
					},
				},
				{
					ControlName: "1.17 - Ensure a support role has been created to manage incidents with AWS Support",
					SecoCloudRules: []types.Rule{
						iam.SupportPolicy{},
					},
				},
				{
					ControlName:    "1.18 - Ensure IAM instance roles are used for AWS resource access from instances",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName: "1.19 - Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
					SecoCloudRules: []types.Rule{
						iam.ExpiredServerCertificates{},
					},
				},
				{
					ControlName:    "1.20 - Ensure that IAM Access analyzer is enabled for all regions",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName:    "1.21 - Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
			},
		},
		{
			GroupName: "2 Storage",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "2.1.1 - Ensure all S3 buckets employ encryption-at-rest",
					SecoCloudRules: []types.Rule{
						s3.EnableServerSideEncryption{},
					},
				},
				{
					ControlName: "2.1.2 - Ensure S3 Bucket Policy allows HTTPS requests",
					SecoCloudRules: []types.Rule{
						s3.EnforceInTransitEncryption{},
					},
				},
				{
					ControlName: "2.1.3 - Ensure MFA Delete is enable on S3 buckets",
					SecoCloudRules: []types.Rule{
						s3.MFADelete{},
					},
				},
				{
					ControlName:    "2.1.4 - Ensure all data in Amazon S3 has been discovered, classified and secured when required.",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName: "2.1.5 - Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
					SecoCloudRules: []types.Rule{
						s3.BlockPublicAccessConfig{},
					},
				},
				{
					ControlName: "2.2.1 - Ensure EBS Volume Encryption is Enabled in all Regions",
					SecoCloudRules: []types.Rule{
						ec2.EBSAtRestEncrypted{},
					},
				},
				{
					ControlName: "2.3.1 - Ensure that encryption is enabled for RDS Instances",
					SecoCloudRules: []types.Rule{
						rds.InstanceAtRestEncrypted{},
					},
				},
				{
					ControlName: "2.3.2 - Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances",
					SecoCloudRules: []types.Rule{
						rds.InstanceAutoMinorVersionUpgrade{},
					},
				},
				{
					ControlName: "2.3.3 - Ensure that public access is not given to RDS Instance",
					SecoCloudRules: []types.Rule{
						rds.InstanceNotPubliclyAccessible{},
					},
				},
				{
					ControlName:    "2.4.1 - Ensure that encryption is enabled for EFS file systems",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
			},
		},
		{
			GroupName: "3 Logging",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "3.1 – Ensure CloudTrail is enabled in all Regions",
					SecoCloudRules: []types.Rule{
						cloudtrail.EnabledAllRegions{},
					},
				},
				{
					ControlName: "3.2 – Ensure CloudTrail log file validation is enabled",
					SecoCloudRules: []types.Rule{
						cloudtrail.LogFileValidationEnabled{},
					},
				},
				{
					ControlName: "3.3 – Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
					SecoCloudRules: []types.Rule{
						cloudtrail.BucketNotPubliclyAccessible{},
					},
				},
				{
					ControlName: "3.4 – Ensure CloudTrail trails are integrated with CloudWatch Logs",
					SecoCloudRules: []types.Rule{
						cloudtrail.DeliveredToCloudwatch{},
					},
				},
				{
					ControlName:    "3.5 – Ensure AWS Config is enabled in all regions",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName: "3.6 – Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
					SecoCloudRules: []types.Rule{
						cloudtrail.BucketAccessLogging{},
					},
				},
				{
					ControlName: "3.7 – Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
					SecoCloudRules: []types.Rule{
						cloudtrail.TrailsAtRestEncrypted{},
					},
				},
				{
					ControlName: "3.8 - Ensure rotation for customer created symmetric CMKs is enabled",
					SecoCloudRules: []types.Rule{
						kms.RotationEnabledForCMK{},
					},
				},
				{
					ControlName: "3.9 - Ensure VPC flow logging is enabled in all VPCs",
					SecoCloudRules: []types.Rule{
						vpc.EnableFlowLogs{},
					},
				},
				{
					ControlName: "3.10 - Ensure that Object-level logging for write events is enabled for S3 bucket",
					SecoCloudRules: []types.Rule{
						cloudtrail.LogS3ObjectWriteEvents{},
					},
				},
				{
					ControlName: "3.11 - Ensure that Object-level logging for read events is enabled for S3 bucket",
					SecoCloudRules: []types.Rule{
						cloudtrail.LogS3ObjectReadEvents{},
					},
				},
			},
		},
		{
			GroupName: "4 Monitoring",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "4.1 – Ensure a log metric filter and alarm exist for unauthorized API calls",
					SecoCloudRules: []types.Rule{
						cloudwatch.UnauthorizedAPI{},
					},
				},
				{
					ControlName: "4.2 – Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
					SecoCloudRules: []types.Rule{
						cloudwatch.SignInWithoutMFA{},
					},
				},
				{
					ControlName: "4.3 – Ensure a log metric filter and alarm exist for usage of 'root' account",
					SecoCloudRules: []types.Rule{
						cloudwatch.RootAccountUsage{},
					},
				},
				{
					ControlName: "4.4 – Ensure a log metric filter and alarm exist for IAM policy changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.IAMPolicyChanges{},
					},
				},
				{
					ControlName: "4.5 – Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.CloudtrailConfigurationChanges{},
					},
				},
				{
					ControlName: "4.6 – Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
					SecoCloudRules: []types.Rule{
						cloudwatch.AWSConsoleAuthFailures{},
					},
				},
				{
					ControlName: "4.7 – Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
					SecoCloudRules: []types.Rule{
						cloudwatch.CMKDisableOrDelete{},
					},
				},
				{
					ControlName: "4.8 - Ensure a log metric filter and alarm exist for S3 bucket policy changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.BucketPolicyChanges{},
					},
				},
				{
					ControlName: "4.9 – Ensure a log metric filter and alarm exist for AWS Config configuration changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.ConfigConfigurationChanges{},
					},
				},
				{
					ControlName: "4.10 – Ensure a log metric filter and alarm exist for security group changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.SecurityGroupChanges{},
					},
				},
				{
					ControlName: "4.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
					SecoCloudRules: []types.Rule{
						cloudwatch.NACLChanges{},
					},
				},
				{
					ControlName: "4.12 - Ensure a log metric filter and alarm exist for changes to network gateways",
					SecoCloudRules: []types.Rule{
						cloudwatch.NetworkGatewayChanges{},
					},
				},
				{
					ControlName: "4.13 - Ensure a log metric filter and alarm exist for route table changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.RouteTableChanges{},
					},
				},
				{
					ControlName: "4.14 - Ensure a log metric filter and alarm exist for VPC changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.VPCChanges{},
					},
				},
				{
					ControlName: "4.15 - Ensure a log metric filter and alarm exists for AWS Organizations changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.OrganizationChanges{},
					},
				},
				{
					ControlName: "4.16 - Ensure AWS Security Hub is enabled",
					SecoCloudRules: []types.Rule{
						securityhub.EnableSecurityHub{},
					},
				},
			},
		},
		{
			GroupName: "5 Networking",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName:    "5.1 - Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName: "5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
					SecoCloudRules: []types.Rule{
						vpc.BlockPublicServerAdminIngressIpv4{},
					},
				},
				{
					ControlName:    "5.3 - Ensure no security groups allow ingress from ::/0 to remote server administration ports",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName: "5.4 - Ensure the default security group of every VPC restricts all traffic",
					SecoCloudRules: []types.Rule{
						vpc.DefaultSecurityGroupsBlockTraffic{},
					},
				},
				{
					ControlName:    "5.5 - Ensure routing tables for VPC peering are \"least access\"",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
			},
		},
	},
}
