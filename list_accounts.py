import boto3
import os
import assume_role
import pprint

def list_ou_accounts(parent):
    aws_cred_account = os.environ['aws_cred_account']
    account = "<org_master_account>"
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

    response = orgClient.list_accounts_for_parent(
        ParentId=parent
    )
    # print(response)
    for account in response['Accounts']:
        acct = account['Id']
        account_response = orgClient.describe_account(
            AccountId=acct
        )
        print(account_response['Account']['Id'], account_response['Account']['Name'],
              account_response['Account']['Status'])
        # print(account_response['Account']['Id'])


parent_id = '<parent_id>'
# list_ou_accounts(parent_id)
# for parent_id in parent_list:
list_ou_accounts(parent_id)
# list_childern(parent_list)
