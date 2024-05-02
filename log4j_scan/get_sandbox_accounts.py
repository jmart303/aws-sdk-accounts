import boto3
import botocore.exceptions


def run():
    try:
        lambdaClient = boto3.client('lambda')
        print('Invoking retrieve_sandbox_accounts')

        response = lambdaClient.invoke(
            FunctionName='retrieve_sandbox_accounts',
            InvocationType='RequestResponse'
        )
        sandbox_accounts = response['Payload'].read().decode()  # convert bytes into a string
        sandbox_accounts = sandbox_accounts.replace('[', '').replace(']', '').replace('"', '').replace(' ', '')
        sandbox_accounts = sandbox_accounts.split(',')  # convert the string to a list

        return sandbox_accounts
    except botocore.exceptions.ClientError as error:
        print('No access to account ', error)
