import boto3
import os
import assume_role


def list_org():
    aws_cred_account = os.environ['aws_cred_account']
    account = "org_master_account"
    audit_credentials = assume_role.security_audit(aws_cred_account)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    orgClient = boto3.client('organizations', region_name='us-east-1',
                             aws_access_key_id=credentials['AccessKeyId'],
                             aws_secret_access_key=credentials['SecretAccessKey'],
                             aws_session_token=credentials['SessionToken']
                             )

    response = orgClient.list_organizational_units_for_parent(
        ParentId='<root_id_of_master_account>'
    )
    for item in response['OrganizationalUnits']:
        print(item)
        # print(item['Id'])


list_org()
