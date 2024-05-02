import os
import boto3
import assume_role
import list_accounts
import describe_instance
import botocore.exceptions
import build_report

dev_sec_prod = os.environ['AWS_ACCOUNT']
parent_id = '<parent_id>'


def get_instance_details():
    region = ''
    regency_instance_list = []
    sandbox_accounts = list_accounts.list_ou_accounts(parent_id)

    region_list = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
                   'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
                   'eu-west-2', 'eu-west-3', 'eu-north-1', 'sa-east-1']
    try:
        for account in sandbox_accounts:
            print('searching account ', account)
            for region in region_list:
                print('searching region ', region)
                audit_credentials = assume_role.security_audit(dev_sec_prod)
                access_key = audit_credentials['AccessKeyId']
                secret_access_key = audit_credentials['SecretAccessKey']
                session_key = audit_credentials['SessionToken']
                credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
                account_access_key = credentials['AccessKeyId']
                account_secret_access_key = credentials['SecretAccessKey']
                account_session_key = credentials['SessionToken']

                ec2Resource = boto3.resource('ec2',
                                             region_name=region,
                                             aws_access_key_id=account_access_key,
                                             aws_secret_access_key=account_secret_access_key,
                                             aws_session_token=account_session_key
                                             )

                ec2Client = boto3.client('ec2', region_name=region,
                                         aws_access_key_id=account_access_key,
                                         aws_secret_access_key=account_secret_access_key,
                                         aws_session_token=account_session_key
                                         )

                instances = ec2Resource.instances.all()
                for instance in instances:
                    # describe_instance.instance_data(account, region, ec2Client, instance.id, ec2Resource)
                    regency_instance_list.append(instance.id)
                    df_rule = describe_instance.instance_data(account, region, ec2Client, instance.id, ec2Resource)
                    print(df_rule)
                    try:
                        if len(df_rule) != 0:
                            build_report.write_dataframe(df_rule, account, region)
                    except TypeError as error:
                        print(error)
                        pass
    except botocore.exceptions.ClientError as error:
        print('No access to region', region, error)


if __name__ == "__main__":
    get_instance_details()
