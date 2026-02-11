import boto3
import sys

def check_opa_instance():
    ec2 = boto3.client('ec2', region_name='ap-south-1')
    
    # filters based on tags in main.tf (though specific tags weren't explicitly seen in the snippet, 
    # aws_instance.opa_server usually has Name tag if configured, or we search by security group or state)
    # The snippet didn't show tags block for aws_instance. 
    # But we know the IP from logs: 3.110.223.83
    
    try:
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
            ]
        )
        
        found = False
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                public_ip = instance.get('PublicIpAddress', 'N/A')
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                launch_time = instance['LaunchTime']
                
                # Check if this matches our expected KeyName
                key_name = instance.get('KeyName')
                if key_name == 'opa_server_key_pair' and state in ['running', 'pending']:
                    print(f"FOUND OPA INSTANCE: {instance_id}")
                    print(f"  Public IP: {public_ip}")
                    print(f"  State: {state}")
                    print(f"  Launch Time: {launch_time}")
                    found = True
                    
                    # Optional: Print tags to confirm
                    tags = instance.get('Tags', [])
                    print(f"  Tags: {tags}")
                    
        if not found:
            print("Could not find OPA instance with key 'opa_server_key_pair'.")
            # Print all running instances just in case
            print("\nAll running instances:")
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    print(f"  {instance['InstanceId']} - {instance.get('PublicIpAddress')} - {instance.get('Tags')}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_opa_instance()
