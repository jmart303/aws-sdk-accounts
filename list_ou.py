import json
import pprint
import boto3
import credentials


def get_ous(listOUs, count):
    ou_dict = {
        listOUs['OrganizationalUnits'][count]['Name'], listOUs['OrganizationalUnits'][count]['Id']
    }
    return ou_dict


def get_credentials():
    # aws_cred_account = os.environ['aws_cred_account']
    account = "<org_master_account>"

    audit_credentials = credentials.get_audit_credentials(account)
    access_key = audit_credentials['AccessKeyId']
    secret_access_key = audit_credentials['SecretAccessKey']
    session_key = audit_credentials['SessionToken']
    #

    orgClient = boto3.client('organizations', region_name='us-east-1',
                             aws_access_key_id=access_key,
                             aws_secret_access_key=secret_access_key,
                             aws_session_token=session_key
                             )
    listRoots = orgClient.list_roots(
    )
    print(listRoots)
    # root_id = listRoots['Roots'][0]['Id']
    # print(f'root id {root_id}')
    # listOUs = orgClient.list_organizational_units_for_parent(
    #     ParentId=root_id
    # )
    # pprint.PrettyPrinter(width=10).pprint(listOUs)

    # print("Type the Account you would like to look up: ")
    # my_input = input("'IT', 'IOT', 'Sandbox' : ").upper()
    # print(my_input)
    count = 0
    new_list = []
    # try:
    #     for ou in listOUs:
    #         print(ou)
    #         print('\n')
    #     while listOUs:
    #         my_list = get_ous(listOUs, count)
    #         count += 1
    #         new_list.append(my_list)
    # except IndexError as error:
    #     print('IndexError ', error)
    # finally:
    #     print(new_list)


if __name__ == "__main__":
    get_credentials()
