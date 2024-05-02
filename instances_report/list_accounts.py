import boto3
import os
import assume_role


def list_ou_accounts(parent_id):
    cred_account = os.environ['AWS_CRED_ACCOUNT']
    account = "<master_ord_account>"
    audit_credentials = assume_role.security_audit(cred_account)

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
        ParentId=parent_id
    )
    count = 0
    sandbox_accounts = []
    while response:
        try:
            account = response['Accounts'][count]['Id']
            account_response = orgClient.describe_account(
                AccountId=account
            )
            sandbox_accounts.append(account_response['Account']['Id'])
            count += 1

        except IndexError as error:
            print('No more accounts', error)
            break

    return sandbox_accounts
