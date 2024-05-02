def get_details(instance, ec2Client):
    response = ec2Client.describe_instances(
        InstanceIds=[
            instance,
        ],
        DryRun=False,
    )
    state = response['Reservations'][0]['Instances'][0]['State']['Code']
    return state
