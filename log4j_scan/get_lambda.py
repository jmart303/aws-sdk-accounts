import boto3
import botocore.exceptions


def run():
    try:
        lambdaClient = boto3.client('lambda')
        print('Invoking retrieve_dde_accounts')

        response = lambdaClient.invoke(
            FunctionName='retrieve_dde_accounts',
            InvocationType='RequestResponse'
        )
        accounts = response['Payload'].read().decode()  # convert bytes into a string
        accounts = accounts.replace('[', '').replace(']', '').replace('"', '').replace(' ', '')
        accounts = accounts.split(',')  # convert the string to a list

        return accounts
    except botocore.exceptions.ClientError as error:
        print('No access to account ', error)
