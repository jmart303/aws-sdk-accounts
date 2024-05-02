import boto3
import assume_role


def list_root():
    aws_cred = "<aws_cred-account>"
    account = "<org_master_account>"
    audit_credentials = assume_role.security_audit(aws_cred)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    orgClient = boto3.client('organizations', region_name='us-east-1',
                             aws_access_key_id=credentials['AccessKeyId'],
                             aws_secret_access_key=credentials['SecretAccessKey'],
                             aws_session_token=credentials['SessionToken']
                             )

    # List the Root organization
    # ----------------------------
    listRoots = orgClient.list_roots(
    )
    root_id = listRoots['Roots'][0]['Id']
    print('got root id ', root_id)

    # ------------------------------------------
    # List the Parent of a child organization
    # -----------------------------------------
    # response = orgClient.list_parents(
    #     ChildId='<child_id>'
    # )
    # print(response)


list_root()
