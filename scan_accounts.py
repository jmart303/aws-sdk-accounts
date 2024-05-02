import boto3
import assume_role

'''
Pull all accounts from the master org account in AWS
'''


def list_accounts(creds):
    access_key = creds['AccessKeyId']
    secret_access_key = creds['SecretAccessKey']
    session_key = creds['SessionToken']

    org_client = boto3.client('organizations',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_access_key,
                              aws_session_token=session_key
                              )

    paginator = org_client.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    with open('accounts/accounts_list.txt', 'w') as file:
        for page in page_iterator:
            for acct in page['Accounts']:
                account_id = acct['Id']
                name = acct['Name']
                status = acct['Status']
                file.write(f'{status} {account_id} - {name} \n')


def get_credentials():
    cred_account = "<account_id>"
    master_account = "m_account_id"

    audit_credentials = assume_role.security_audit(cred_account)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    credentials = assume_role.audit(master_account, access_key, secret_access_key, session_key)
    list_accounts(credentials)


get_credentials()
