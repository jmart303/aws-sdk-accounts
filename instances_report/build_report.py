import pandas as pd
import openpyxl
import xlsxwriter
from datetime import datetime


# import aws_uploader


def save_report(df, account, region):
    date = datetime.now().strftime("%d-%m-%Y_%I:%M:%S")
    report_data = account + '-' + region + '-regency-security-report-' + date + '.xlsx'
    writer = pd.ExcelWriter(report_data, engine='xlsxwriter')
    df.to_excel(writer, sheet_name=account)
    print('saved report')
    print(report_data)
    writer.save()
    # aws_uploader.upload_to_aws(report_data, report_data)


def write_dataframe(df_rule, account, region):
    df = pd.DataFrame()
    df = df.append(df_rule)
    print('DF', df)
    save_report(df, account, region)


def write_data(account, region, rule, instance_id):
    data = {
        "account": account,
        "region": region,
        "instance": instance_id,
        "rule violation": [rule]
    }

    return data
