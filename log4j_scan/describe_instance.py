def get_instance_data(ec2Client, instance_id):
    response = ec2Client.describe_instances(
        InstanceIds=[
            instance_id,
        ],
        DryRun=False,
    )
    try:
        public_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        return public_ip

    except KeyError as e:
        pass
