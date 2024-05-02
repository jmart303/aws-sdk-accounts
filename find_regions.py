import boto3
import os
import assume_role
import botocore.exceptions


def get_credentials():
    aws_cred_account = os.environ['aws_cred_account']
    my_file = open("../security_audit/sandbox_accounts.txt", "r")
    content = my_file.read()
    content_list = content.split(",")
    for acct in content_list:
        try:
            account = acct
            audit_credentials = assume_role.security_audit(aws_cred_account)

            access_key = audit_credentials['AccessKeyId']
            secret_access_key = audit_credentials['SecretAccessKey']
            session_key = audit_credentials['SessionToken']

            credentials = assume_role.audit(account, access_key, secret_access_key, session_key)

            ec2Client = boto3.client('ec2',
                                     aws_access_key_id=credentials['AccessKeyId'],
                                     aws_secret_access_key=credentials['SecretAccessKey'],
                                     aws_session_token=credentials['SessionToken']
                                     )

            region_list = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
                           'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
                           'eu-west-2', 'eu-west-3', 'eu-north-1', 'sa-east-1']

            for region in region_list:
                response = ec2Client.describe_regions(

                    RegionNames=[
                        region,
                    ]
                )
                region_endpoint = response['Regions'][0]['Endpoint']
                region_status = response['Regions'][0]['OptInStatus']
                if region_status == 'opt-in-not-required':
                    print(acct, region_endpoint, region_status)

        except botocore.exceptions.ClientError as error:
            print('No Access ', error)


get_credentials()

