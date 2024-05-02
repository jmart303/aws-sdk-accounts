import boto3
import os
import assume_role
import colorama
from colorama import Fore, Style


def pull_sgs():
    aws_cred_account = os.environ['aws_cred_account']
    audit_credentials = assume_role.security_audit(aws_cred_account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    # account where the SG is.
    account = "<account_id>"
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)

    region_list = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
                   'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
                   'eu-west-2', 'eu-west-3', 'eu-north-1', 'sa-east-1']
    for region in region_list:
        ec2Resource = boto3.resource('ec2',
                                     region_name=region,
                                     aws_access_key_id=credentials['AccessKeyId'],
                                     aws_secret_access_key=credentials['SecretAccessKey'],
                                     aws_session_token=credentials['SessionToken']
                                     )

        ec2Client = boto3.client('ec2',
                                 region_name=region,
                                 aws_access_key_id=credentials['AccessKeyId'],
                                 aws_secret_access_key=credentials['SecretAccessKey'],
                                 aws_session_token=credentials['SessionToken']
                                 )

        security_groups = ec2Resource.security_groups.all()
        orig_count = 0
        team_count = 0
        for sg in security_groups:
            # print(sg)
            response = ec2Client.describe_security_groups(
                GroupIds=[
                    sg.id,
                ],
                DryRun=False,
            )
            try:
                group_name = response['SecurityGroups'][0]['GroupName']
                tags = response['SecurityGroups'][0]['Tags']
                # print('TAGS', tags, sg)
                for tag in tags:
                    if 'Security Violation' in tag['Key']:
                        print(Fore.GREEN + 'ORIG FOUND', sg, tags)
                        orig_count += 1
                        continue
                    if 'Security Violation Software Not Installed' in tag['Key'] or 'Security Violation Not Installed ' in tag['Key']:
                        team_count += 1
                        print(Fore.GREEN + 'FOUND', sg, tags)
                        continue
                    else:
                        print(Fore.CYAN + 'UNKOWN', sg, tags)
            except KeyError as e:
                pass
                # print('no key', e)
        print('Team TOTAL', team_count)
        print('ORIG TOTAL', orig_count)


pull_sgs()
