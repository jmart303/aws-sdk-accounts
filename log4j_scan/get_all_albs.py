
import boto3
import botocore.exceptions
import assume_role
import scan_accounts
import get_aws_services

from boto3.session import Session

aws_cred_account = '<aws_credentials_account>'


def get_instance_details(audit_credentials):
    region = ''
    instance_list = []
    s = Session()
    region_list = s.get_available_regions('ec2')

    accounts = scan_accounts.list_accounts(audit_credentials)
    try:
        for account in accounts:
            try:
                for region in region_list:
                    print(f'searching ', account, ' in region ', region)
                    enforce = assume_role.enforce(account)
                    # enforce_credentials = assume_role.security_enforce(account)
                    account_access_key = enforce['AccessKeyId']
                    account_secret_access_key = enforce['SecretAccessKey']
                    account_session_key = enforce['SessionToken']

                    ec2Resource = get_aws_services.get_ec2_resource(region, account_access_key,
                                                                    account_secret_access_key,
                                                                    account_session_key)

                    ec2Client = get_aws_services.get_ec2_client(region, account_access_key,
                                                                account_secret_access_key,
                                                                account_session_key)

                    elbClient = get_aws_services.get_ec2_client(region, account_access_key,
                                                                account_secret_access_key,
                                                                account_session_key)
                    instances = ec2Resource.instances.all()
                    result_set = {}
                    for instance in instances:
                        instances_description = ec2Client.describe_instances(
                            Filters=[
                                {'Name': 'instance-id',
                                 'Values': [
                                     instance.id
                                 ]}
                            ]
                        )
                        for inst in instances_description['Reservations']:
                            for insta in inst["Instances"]:
                                result_set["State"]=insta["State"]["Name"]
                                for tag in insta["Tags"]:
                                    print(tag)
                                # print(result_set)
                    session = boto3.session.Session()
                    elb = session.client('elb')
                    lbs = elb.describe_load_balancers(PageSize=400)
                    for lb in lbs["LoadBalancerDescriptions"]:
                        print("\n"*2)
                        print ("-"*6)
                        print("Name:", lb["LoadBalancerName"])
                        print("HealthCheck:", lb["HealthCheck"])
                        print("Instance Info:")
                        if len(lb["Instances"]) > 0:
                            for instance in lb["Instances"]:
                                instance.update(instance["InstanceId"])
                                print(instance)

            except botocore.exceptions.ClientError as error:
                print('No access to region', region, error)

    except botocore.exceptions.ClientError as error:
        print('No access to account', region, error)


if __name__ == "__main__":

    org_master_account = "<org_master_account>"
    audit_credentials = assume_role.security_audit(aws_cred_account)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    credentials = assume_role.audit(org_master_account, access_key, secret_access_key, session_key)

    get_instance_details(credentials)
