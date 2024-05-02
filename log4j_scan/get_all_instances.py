import botocore.exceptions
import assume_role
import os
import scan_accounts
import get_aws_services
import describe_instance

from boto3.session import Session

# aws_cred_account = '<aws_cred_account>'


def get_instance_details():
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
    #                 enforce_credentials = assume_role.security_enforce(aws_cred_account)
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
                    with open('instance_data.txt', 'a') as file:
                        for instance in instances:
                            pub_ip = describe_instance.get_instance_data(ec2Client, instance.id)
                            if pub_ip is None:
                                continue
                            instancePublicDNS = instance.public_dns_name
                            instance_data = pub_ip + ',' + instancePublicDNS + '\n'
                            file.write(instance_data)
                            print(pub_ip, instancePublicDNS)

    #                 # with open('loadbalancer_data.txt', 'a') as lbfile:
    #                 #     session = boto3.session.Session()
    #                 #     elbClienttst = session.client('elbv2')
    #                 #     lbs = elbClienttst.describe_load_balancers(PageSize=400)
    #                 #     for lb in lbs['LoadBalancers']:
    #                 #         print(lb['DNSName'])
            except botocore.exceptions.ClientError as error:
                print('No access to region', region, error)

    except botocore.exceptions.ClientError as error:
        print('No access to account', region, error)


if __name__ == "__main__":
    aws_cred_account = os.environ['<aws_cred_account>']
    org_master_account = "<org_master_account>"
    audit_credentials = assume_role.security_audit(aws_cred_account)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']

    credentials = assume_role.audit(org_master_account, access_key, secret_access_key, session_key)

    get_instance_details()
