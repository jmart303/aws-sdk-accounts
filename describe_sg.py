import boto3
import os

import botocore.exceptions

import assume_role


def get_credentials():
    aws_cred_account = os.environ['aws_cred_account']
    audit_credentials = assume_role.security_audit(aws_cred_account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    # account where the SG is.
    account = "<account_id>"
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    account_access_key = credentials['AccessKeyId']
    account_secret_access_key = credentials['SecretAccessKey']
    account_session_key = credentials['SessionToken']

    ec2Client = boto3.client(
        'ec2', region_name='us-east-1',
        aws_access_key_id=account_access_key,
        aws_secret_access_key=account_secret_access_key,
        aws_session_token=account_session_key
    )
    try:
        response = ec2Client.describe_security_groups(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        '<vpc_id>',
                    ]
                },
            ],
            GroupIds=[
                # '<sg-id_1>',
                # '<sg-id_2>',
                # '<sg-id_3>',
                # '<sg-id_4>',
                # '<sg-id_5>'
            ],

            DryRun=False,

        )
        print(response['SecurityGroups'][0]['GroupName'])
        print(response['SecurityGroups'][0]['VpcId'])
    except botocore.exceptions.ClientError as error:
        print(error)


# print(response)

# instance_id = response['SecurityGroups'][0]['GroupName'].split(' ')
# instance = instance_id[4].split('=')[0]
# print(instance)

sg_list = ['sg_ids']
get_credentials()
