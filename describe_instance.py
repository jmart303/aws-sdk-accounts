import boto3
import os
import assume_role
from boto3.session import Session
import botocore.exceptions


def get_credentials(instance):
    aws_cred_account = os.environ['aws_cred_account']
    audit_credentials = assume_role.security_audit(aws_cred_account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    # account where the instance is.
    account = "<account>"
    region = 'eu-central-1'
    # credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    audit_credentials = assume_role.security_audit(aws_cred_account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    account_access_key = credentials['AccessKeyId']
    account_secret_access_key = credentials['SecretAccessKey']
    account_session_key = credentials['SessionToken']

    ec2Client = boto3.client('ec2', region_name=region,
                             aws_access_key_id=account_access_key,
                             aws_secret_access_key=account_secret_access_key,
                             aws_session_token=account_session_key
                             )

    ec2Resource = boto3.resource('ec2', region_name='us-west-1',
                                 aws_access_key_id=account_access_key,
                                 aws_secret_access_key=account_secret_access_key,
                                 aws_session_token=account_session_key
                                 )

    try:
        response = ec2Client.describe_instances(
            InstanceIds=[
                instance
            ],
            DryRun=False,
        )
        print(response)
        # print('found instance', response['Reservations'][0]['Instances'][0]['InstanceId'])

        # print(response['Reservations'][0]['Instances'][0]['Tags'])

        # state = response['Reservations'][0]['Instances'][0]['State']
        # print(state)
        # sg_group = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['Groups']
        # net_interfaces = response['Reservations'][0]['Instances'][0]['NetworkInterfaces']
        #
        # public_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        # tags = response['Reservations'][0]['Instances'][0]['Tags']
        # print(sg_group)

        # print(net_interfaces)
        # print(tags)
    except botocore.exceptions.ClientError as e:
        print(e)


if __name__ == '__main__':
    instance_list = ["<list_of_instances>"]
    for inst in instance_list:
        get_credentials(inst)
