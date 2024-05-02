import boto3
import json


def get_dev_account():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(
        SecretId='dev_account'
    )
    secret = response['SecretString']
    formatSecret = json.loads(secret)
    key = formatSecret['account']
    return key


def get_prod_account():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(
        SecretId='prod_account'
    )
    secret = response['SecretString']
    formatSecret = json.loads(secret)
    key = formatSecret['account']
    return key
