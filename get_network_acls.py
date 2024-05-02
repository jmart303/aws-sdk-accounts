import assume_role
import boto3
import os

ports_to_check = [20, 21, 23, 25, 139, 143, 161, 162, 199, 389, 445, 514, 853, 873, 944, 992,
                  1433, 1434, 1521, 1830, 3306, 3389, 3528, 4447, 4712, 4713, 5432, 5445, 5455, 5984,
                  6379, 7000, 7001, 7210, 7473, 7474, 7574, 7600, 8001, 8005, 8009, 8080, 8087, 8090,
                  8098, 8443, 8529, 8983, 9042, 9200, 9300, 9990, 9999, 27017, 27018, 27019, 28015,
                  28017, 29015, 54200, 55200, 57600, 135, 88]


def is_public_acls(net_acls, ports_to_check):
    public_acls = {}

    for network_acl in net_acls:
        rules = network_acl.entries
        acl_id = network_acl.network_acl_id
        attached_subnets = [assoc['SubnetId'] for assoc in network_acl.associations]

        # If acl is not attached to any subnets no need to report.
        if not attached_subnets:
            continue

        # rules = filter(lambda rule: (
        #         rule['RuleAction'] == 'allow' and rule['CidrBlock'] == '0.0.0.0/0' and
        #         not (rule['Egress'] or 'Ipv6CidrBlock' in rule)
        # ), rules)

        # rules = filter(lambda rule: (
        #         rule['RuleAction'] == 'allow' and rule['CidrBlock'] == '0.0.0.0/0' and
        #         (rule['Ingress'] == "True" or 'Ipv6CidrBlock' in rule)
        # ), rules)

        for rule in rules:
            print(rule)
            if rule['Protocol'] == '-1':
                print(' ')
                # print(public_acls, acl_id, attached_subnets, 'All')
                # _append_public_acls(public_acls, acl_id, attached_subnets, 'All')
            elif 'PortRange' in rule:
                for port in ports_to_check:
                    if int(rule['PortRange']['From']) <= int(port) <= int(rule['PortRange']['To']):
                        print(' ')
                        # print(public_acls, acl_id, attached_subnets, int(port))
                        # _append_public_acls(public_acls, acl_id, attached_subnets, int(port))

    return public_acls


def get_credentials():
    aws_cred_account = os.environ['aws_cred_account']
    # account = get_account_id.get_dev_account()

    audit_credentials = assume_role.security_audit(aws_cred_account)

    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    account = "<account_id>"
    credentials = assume_role.audit(account, access_key, secret_access_key, session_key)
    # print(credentials)
    # account_access_key = credentials['AccessKeyId']
    # account_secret_access_key = credentials['SecretAccessKey']
    # account_session_key = credentials['SessionToken']
    # account_credentials = assume_role.account_credentials(account, access_key, secret_access_key, session_key)

    ec2Resource = boto3.resource('ec2',
                                 region_name='us-east-1',
                                 aws_access_key_id=credentials['AccessKeyId'],
                                 aws_secret_access_key=credentials['SecretAccessKey'],
                                 aws_session_token=credentials['SessionToken']
                                 )

    network_acls = ec2Resource.network_acls.all()
    is_public_acls(network_acls, ports_to_check)


get_credentials()
