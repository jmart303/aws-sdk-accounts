import boto3


def get_elb_client(region, enforce_account_access_key, enforce_account_secret_access_key, enforce_account_session_key):
    elbSession = boto3.resource('elb',
                               region_name=region,
                               aws_access_key_id=enforce_account_access_key,
                               aws_secret_access_key=enforce_account_secret_access_key,
                               aws_session_token=enforce_account_session_key
                               )
    return elbSession

def get_elb_client(region, enforce_account_access_key, enforce_account_secret_access_key, enforce_account_session_key):
    elbClient = boto3.client('elb',
                                 region_name=region,
                                 aws_access_key_id=enforce_account_access_key,
                                 aws_secret_access_key=enforce_account_secret_access_key,
                                 aws_session_token=enforce_account_session_key
                                 )
    return elbClient


def get_elbv2_client(region, enforce_account_access_key, enforce_account_secret_access_key, enforce_account_session_key):
    elbv2Client = boto3.client('elbv2',
                               region_name=region,
                               aws_access_key_id=enforce_account_access_key,
                               aws_secret_access_key=enforce_account_secret_access_key,
                               aws_session_token=enforce_account_session_key
                               )
    return elbv2Client


def get_ec2_resource(region, enforce_account_access_key, enforce_account_secret_access_key,
                     enforce_account_session_key):
    ec2Resource = boto3.resource('ec2',
                                 region_name=region,
                                 aws_access_key_id=enforce_account_access_key,
                                 aws_secret_access_key=enforce_account_secret_access_key,
                                 aws_session_token=enforce_account_session_key
                                 )
    return ec2Resource


def get_ec2_client(region, enforce_account_access_key, enforce_account_secret_access_key, enforce_account_session_key):
    ec2Client = boto3.client('ec2', region_name=region,
                             aws_access_key_id=enforce_account_access_key,
                             aws_secret_access_key=enforce_account_secret_access_key,
                             aws_session_token=enforce_account_session_key
                             )

    return ec2Client


def get_dynamodb_client(default_region, credentials):
    dynamodbClient = boto3.client('dynamodb',
                                  region_name=default_region,  # The account where the DB lives
                                  aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'],
                                  aws_session_token=credentials['SessionToken']
                                  )
    return dynamodbClient


def get_dynamodb_resource(default_region, credentials):
    dynamodbResource = boto3.resource('dynamodb',
                                      region_name=default_region,  # The account where the DB lives
                                      aws_access_key_id=credentials['AccessKeyId'],
                                      aws_secret_access_key=credentials['SecretAccessKey'],
                                      aws_session_token=credentials['SessionToken']
                                      )
    return dynamodbResource
