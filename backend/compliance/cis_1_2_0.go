package compliance

import (
	"github.com/SecoCloud/SecoCloud/rules/cloudtrail"
	"github.com/SecoCloud/SecoCloud/rules/cloudwatch"
	"github.com/SecoCloud/SecoCloud/rules/iam"
	"github.com/SecoCloud/SecoCloud/rules/kms"
	"github.com/SecoCloud/SecoCloud/rules/types"
	"github.com/SecoCloud/SecoCloud/rules/vpc"
)

var Cis_1_2_0_Spec ComplianceFrameworkSpec = ComplianceFrameworkSpec{
	FrameworkName: "CIS 1.2.0",
	ComplianceControlGroupSpecs: []ComplianceControlGroupSpec{
		{
			GroupName: "1 Identity and Access Management",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "1.1 - Avoid the use of the \"root\" account",
					SecoCloudRules: []types.Rule{
						iam.RootAccountUsed{},
					},
				},
				{
					ControlName: "1.2 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
					SecoCloudRules: []types.Rule{
						iam.MfaEnabledForConsoleAccess{},
					},
				},
				{
					ControlName: "1.3 - Ensure credentials unused for 90 days or greater are disabled",
					SecoCloudRules: []types.Rule{
						iam.CredentialsUnused90Days{},
					},
				},
				{
					ControlName: "1.4 - Ensure access keys are rotated every 90 days or less",
					SecoCloudRules: []types.Rule{
						iam.AccessKeysRotated90Days{},
					},
				},
				{
					ControlName: "1.5 - Ensure IAM password policy requires at least one uppercase letter",
					SecoCloudRules: []types.Rule{
						iam.PasswordUppercaseRequired{},
					},
				},
				{
					ControlName: "1.6 - Ensure IAM password policy require at least one lowercase letter",
					SecoCloudRules: []types.Rule{
						iam.PasswordLowercaseRequired{},
					},
				},
				{
					ControlName: "1.7 - Ensure IAM password policy require at least one symbol",
					SecoCloudRules: []types.Rule{
						iam.PasswordSymbolsRequired{},
					},
				},
				{
					ControlName: "1.8 - Ensure IAM password policy require at least one number",
					SecoCloudRules: []types.Rule{
						iam.PasswordNumbersRequired{},
					},
				},
				{
					ControlName: "1.9 - Ensure IAM password policy requires minimum length of 14 or greater",
					SecoCloudRules: []types.Rule{
						iam.PasswordMinLength{},
					},
				},
				{
					ControlName: "1.10 - Ensure IAM password policy prevents password reuse",
					SecoCloudRules: []types.Rule{
						iam.PasswordReusePrevention{},
					},
				},
				{
					ControlName: "1.11 - Ensure IAM password policy expires passwords within 90 days or less",
					SecoCloudRules: []types.Rule{
						iam.PasswordExpiry{},
					},
				},
				{
					ControlName: "1.12 – Ensure no root user access key exists",
					SecoCloudRules: []types.Rule{
						iam.NoRootAccessKeys{},
					},
				},
				{
					ControlName: "1.13 - Ensure MFA is enabled for the \"root\" account ",
					SecoCloudRules: []types.Rule{
						iam.RootMfaEnabled{},
					},
				},
				{
					ControlName:    "1.14 - Ensure hardware MFA is enabled for the \"root\" account",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName:    "1.15 - Ensure security questions are registered in the AWS account",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName: "1.16 - Ensure IAM policies are attached only to groups or roles",
					SecoCloudRules: []types.Rule{
						iam.NoUserPolicies{},
					},
				},
				{
					ControlName:    "1.17 - Maintain current contact details",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName:    "1.18 - Ensure security contact information is registered",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName:    "1.19 - Ensure IAM instance roles are used for AWS resource access from instances",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
				{
					ControlName: "1.20 - Ensure a support role has been created to manage incidents with AWS Support",
					SecoCloudRules: []types.Rule{
						iam.SupportPolicy{},
					},
				},
				{
					ControlName: "1.21 - Do not setup access keys during initial user setup for all IAM users that have a console password",
					SecoCloudRules: []types.Rule{
						iam.AvoidAccessKeysAtSetup{},
					},
				},
				{
					ControlName: "1.22 - Ensure IAM policies that allow full \"*:*\" administrative privileges are not created",
					SecoCloudRules: []types.Rule{
						iam.NoStarPolicies{},
					},
				},
			},
		},
		{
			GroupName: "2 Logging",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "2.1 – Ensure CloudTrail is enabled in all Regions",
					SecoCloudRules: []types.Rule{
						cloudtrail.EnabledAllRegions{},
					},
				},
				{
					ControlName: "2.2 – Ensure CloudTrail log file validation is enabled",
					SecoCloudRules: []types.Rule{
						cloudtrail.LogFileValidationEnabled{},
					},
				},
				{
					ControlName: "2.3 – Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
					SecoCloudRules: []types.Rule{
						cloudtrail.BucketNotPubliclyAccessible{},
					},
				},
				{
					ControlName: "2.4 – Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs",
					SecoCloudRules: []types.Rule{
						cloudtrail.DeliveredToCloudwatch{},
					},
				},
				{
					ControlName:    "2.5 – Ensure AWS Config is enabled",
					SecoCloudRules: []types.Rule{},
					Comment:        "SecoCloud is working on rule(s) to verify this control.",
				},
				{
					ControlName: "2.6 – Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
					SecoCloudRules: []types.Rule{
						cloudtrail.BucketAccessLogging{},
					},
				},
				{
					ControlName: "2.7 – Ensure CloudTrail logs are encrypted at rest using AWS KMS keys",
					SecoCloudRules: []types.Rule{
						cloudtrail.TrailsAtRestEncrypted{},
					},
				},
				{
					ControlName: "2.8 – Ensure rotation for customer-created KMS keys is enabled",
					SecoCloudRules: []types.Rule{
						kms.RotationEnabledForCMK{},
					},
				},
				{
					ControlName: "2.9 – Ensure VPC flow logging is enabled in all VPCs",
					SecoCloudRules: []types.Rule{
						vpc.EnableFlowLogs{},
					},
				},
			},
		},
		{
			GroupName: "3 Monitoring",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "3.1 – Ensure a log metric filter and alarm exist for unauthorized API calls",
					SecoCloudRules: []types.Rule{
						cloudwatch.UnauthorizedAPI{},
					},
				},
				{
					ControlName: "3.2 – Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
					SecoCloudRules: []types.Rule{
						cloudwatch.SignInWithoutMFA{},
					},
				},
				{
					ControlName: "3.3 – Ensure a log metric filter and alarm exist for usage of \"root\" account",
					SecoCloudRules: []types.Rule{
						cloudwatch.RootAccountUsage{},
					},
				},
				{
					ControlName: "3.4 – Ensure a log metric filter and alarm exist for IAM policy changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.IAMPolicyChanges{},
					},
				},
				{
					ControlName: "3.5 – Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.CloudtrailConfigurationChanges{},
					},
				},
				{
					ControlName: "3.6 – Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
					SecoCloudRules: []types.Rule{
						cloudwatch.AWSConsoleAuthFailures{},
					},
				},
				{
					ControlName: "3.7 – Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
					SecoCloudRules: []types.Rule{
						cloudwatch.CMKDisableOrDelete{},
					},
				},
				{
					ControlName: "3.8 – Ensure a log metric filter and alarm exist for S3 bucket policy changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.BucketPolicyChanges{},
					},
				},
				{
					ControlName: "3.9 – Ensure a log metric filter and alarm exist for AWS Config configuration changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.ConfigConfigurationChanges{},
					},
				},
				{
					ControlName: "3.10 – Ensure a log metric filter and alarm exist for security group changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.SecurityGroupChanges{},
					},
				},
				{
					ControlName: "3.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
					SecoCloudRules: []types.Rule{
						cloudwatch.NACLChanges{},
					},
				},
				{
					ControlName: "3.12 - Ensure a log metric filter and alarm exist for changes to network gateways",
					SecoCloudRules: []types.Rule{
						cloudwatch.NetworkGatewayChanges{},
					},
				},
				{
					ControlName: "3.13 - Ensure a log metric filter and alarm exist for route table changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.RouteTableChanges{},
					},
				},
				{
					ControlName: "3.14 - Ensure a log metric filter and alarm exist for VPC changes",
					SecoCloudRules: []types.Rule{
						cloudwatch.VPCChanges{},
					},
				},
			},
		},
		{
			GroupName: "4 Networking",
			ComplianceControlSpecs: []ComplianceControlSpec{
				{
					ControlName: "4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
					SecoCloudRules: []types.Rule{
						vpc.BlockPublicServerAdminIngressIpv4{},
					},
				},
				{
					ControlName: "4.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 ",
					SecoCloudRules: []types.Rule{
						vpc.BlockPublicServerAdminIngressIpv4{},
					},
				},
				{
					ControlName: "4.3 - Ensure the default security group of every VPC restricts all traffic",
					SecoCloudRules: []types.Rule{
						vpc.DefaultSecurityGroupsBlockTraffic{},
					},
				},
				{
					ControlName:    "4.4 - Ensure routing tables for VPC peering are \"least access\"",
					SecoCloudRules: []types.Rule{},
					Comment:        "This control requires manual verification.",
				},
			},
		},
	},
}
