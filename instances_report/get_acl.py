import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)


def append_public_acls(public_acls, acl_id, subnet_id, rule_type):
    if subnet_id in public_acls:
        public_acls[subnet_id]['Rules'].append({'PortType': rule_type})
    else:
        public_acls[subnet_id] = {
            'SubnetId': subnet_id,
            'ACLId': acl_id,
            'Rules': [{'PortType': rule_type}],
        }

    return public_acls


def pub_acls(subnet_id, ec2Resource, ports_to_check):
    network_acls = ec2Resource.network_acls.all()
    public_acls = {}
    for acl in network_acls:
        rules = acl.entries
        acl_id = acl.id
        attached_subnets = [assoc['SubnetId'] for assoc in acl.associations]
        for subnet in attached_subnets:
            if subnet_id != subnet:
                continue
            if subnet_id == subnet:
                logger.info('Found matching subnet')
                rules = filter(lambda rule: (
                        rule['RuleAction'] == 'allow' and rule['CidrBlock'] == '0.0.0.0/0' and
                        not (rule['Egress'] or 'Ipv6CidrBlock' in rule)
                ), rules)
                logger.info('Checking for external rules')
                for rule in rules:
                    if rule['Protocol'] == '-1':
                        append_public_acls(public_acls, acl_id, subnet_id, 'All')
                    elif 'PortRange' in rule:
                        for port in ports_to_check:
                            if int(rule['PortRange']['From']) <= int(port) <= int(rule['PortRange']['To']):
                                append_public_acls(public_acls, acl_id, subnet_id, int(port))

                return public_acls


