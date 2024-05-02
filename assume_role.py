import boto3
from boto3.session import Session


def security_audit(account):
    sts_client = boto3.client('sts')

    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::' + account + ':role/securityAudit',
        RoleSessionName='AssumeRoleSecurityAuditSession'
    )
    credentials = assumed_role_object['Credentials']
    return credentials


def audit(account, access_key, secret_access_key, session_key):

    session = Session(aws_access_key_id=access_key,
                      aws_secret_access_key=secret_access_key,
                      aws_session_token=session_key)

    sts_client = session.client('sts')

    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::' + account + ':role/audit',
        RoleSessionName='AssumeRoleAuditSession'
    )

    credentials = assumed_role_object['Credentials']
    return credentials


def account_credentials(account, access_key, secret_access_key, session_key):

    session = Session(aws_access_key_id=access_key,
                      aws_secret_access_key=secret_access_key,
                      aws_session_token=session_key)

    sts_client = session.client('sts')

    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::' + account + ':role/audit',
        RoleSessionName='AssumeRoleAuditSession'
    )

    credentials = assumed_role_object['Credentials']
    return credentials


