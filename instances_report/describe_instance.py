import pandas as pd
import get_acl
import build_report

ports_to_check = [3, 4, 6, 8, 20, 22, 53, 21, 23, 25, 139, 143, 161, 162, 199, 389, 445, 514, 853, 873, 944, 992,
                  1433, 1434, 1521, 1830, 3306, 3389, 3528, 4447, 4712, 4713, 5432, 5445, 5455, 5984,
                  6379, 7000, 7001, 7210, 7473, 7474, 7574, 7600, 8001, 8005, 8009, 8080, 8087, 8090,
                  8098, 8443, 8529, 8983, 9042, 9200, 9300, 9990, 9999, 27017, 27018, 27019, 28015,
                  28017, 29015, 54200, 55200, 57600, 135, 88]


def tag_lookup(instance_security_group):
    try:
        for tags in instance_security_group.tags:
            if tags['Key'] == 'Security Violation':
                return instance_security_group.id
    except TypeError as error:
        print('tag check, no violation tag found', error)
        pass


def validate_rule(ingress, account, region, instance_id):
    data_list = []
    for rule in ingress:
        if 'IpProtocol' not in rule:
            continue
        if rule['IpProtocol'] == '-1' and '0.0.0.0/0' in str(rule['IpRanges']):
            report_data = build_report.write_data(account, region, rule, instance_id)
            data_list.append(report_data)
            print('OPEN RULE ', rule)
            continue
        if '0.0.0.0/0' in str(rule['IpRanges']) and rule['IpProtocol'] != 'icmp':
            try:
                from_port = int(rule['FromPort'])
                to_port = int(rule['ToPort'])
                matched_port = [p for p in ports_to_check if from_port <= int(p) <= to_port]
                if matched_port:
                    report_data = build_report.write_data(account, region, rule, instance_id)
                    data_list.append(report_data)
                    print('OPEN RULE and port ', rule)
            except KeyError as error:
                print('KeyError, key not found', error)
                pass

    df_rule = pd.DataFrame(data_list)

    return df_rule


def instance_data(account, region, ec2Client, instance_id, ec2Resource):
    df_rule = pd.DataFrame
    try:
        response = ec2Client.describe_instances(
            InstanceIds=[
                instance_id,
            ],
            DryRun=False,
        )
        # state = response['Reservations'][0]['Instances'][0]['State']['Name']
        # print('Instance', instance_id, state)
        try:
            print('validating Instance ', instance_id)
            # print(response['Reservations'][0]['Instances'][0]['InstanceId'])
            # subnet_id = response['Reservations'][0]['Instances'][0]['SubnetId']
            # public_acl = get_acl.pub_acls(subnet_id, ec2Resource, ports_to_check)
            # try:
            #     public_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
            #     try:
            #         instance_security_group = response['Reservations'][0]['Instances'][0]['SecurityGroups'][0][
            #             'GroupId']
            #         security_group = ec2Resource.SecurityGroup(instance_security_group)
            #         ingress = security_group.ip_permissions
            #         print('Rule', ingress)
            #         if public_ip and public_acl:
            #             try:
            #                 df_rule = validate_rule(ingress, account, region, instance_id)
            #                 # sg_instance_id = tag_lookup(security_group)
            #                 # print(account, instance_id, sg_instance_id)
            #                 # return df_rule
            #             except:
            #                 print('no SG')
            #     except KeyError as error:
            #         print('no security group ', error)
            # except KeyError as error:
            #     print('no public ip ', error)
        except KeyError as error:
            error = str(error)
            if 'CidrBlock' in error:
                print('No pub ACL', error)
            else:
                print('No Subnet', error)
    except KeyError as error:
        print('no response ', error)

    return df_rule
