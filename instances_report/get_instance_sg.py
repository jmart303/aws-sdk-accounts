import boto3
import os
import assume_role


def get_sg(inst):
    dev_sec_prod = os.environ['AWS_CRED_ACCOUNT']
    audit_credentials = assume_role.security_audit(dev_sec_prod)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    # account where the SG is.
    account = "<aws_account_to_query>"
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    account_access_key = credentials['AccessKeyId']
    account_secret_access_key = credentials['SecretAccessKey']
    account_session_key = credentials['SessionToken']

    ec2Client = boto3.client('ec2', region_name='us-east-1',
                             aws_access_key_id=account_access_key,
                             aws_secret_access_key=account_secret_access_key,
                             aws_session_token=account_session_key
                             )

    response = ec2Client.describe_instances(
        InstanceIds=[
            inst,
        ],
        DryRun=False,
    )
    print(response)
    instance_id = response['SecurityGroups'][0]['GroupName'].split(' ')
    inst = instance_id[4].split('=')[0]
    print(inst)


with open('instance_id.txt', 'r') as instance_data:
    for instance in instance_data:
        get_sg(instance)
