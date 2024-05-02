import boto3
import os
import assume_role


def get_credentials():
    cred_account = os.environ['cred_account']
    audit_credentials = assume_role.security_audit(cred_account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    # account where the SG is.
    account = os.environ['account']
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    account_access_key = credentials['AccessKeyId']
    account_secret_access_key = credentials['SecretAccessKey']
    account_session_key = credentials['SessionToken']

    ec2Resource = boto3.resource('ec2', region_name='us-east-1',
                             aws_access_key_id=account_access_key,
                             aws_secret_access_key=account_secret_access_key,
                             aws_session_token=account_session_key
                             )

    ec2client = boto3.client('ec2', region_name='us-east-1',
                                 aws_access_key_id=account_access_key,
                                 aws_secret_access_key=account_secret_access_key,
                                 aws_session_token=account_session_key
                                 )

    all_instances = ec2client.describe_instances()
    all_sg = ec2client.describe_security_groups()


    sgs = list(ec2Resource.security_groups.all())
    insts = list(ec2Resource.instances.all())

    all_sgs = set([sg.group_name for sg in sgs])
    all_inst_sgs = set([sg['GroupName'] for inst in insts for sg in inst.security_groups])
    unused_sgs = all_sgs - all_inst_sgs
    print('Total SGs:', len(all_sgs))
    print('SGS attached to instances:', len(all_inst_sgs))
    print('Orphaned SGs:', len(unused_sgs))
    # print('Unattached SG names:', unused_sgs)
    for sg in unused_sgs:
        print(sg)


get_credentials()