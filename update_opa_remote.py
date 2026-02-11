
import boto3
import time
import sys
import os

def update_opa_config(instance_id):
    ssm = boto3.client('ssm', region_name='ap-south-1')
    
    # Read the updated Rego files
    base_path = r'd:\Projects\CSPM\serverless-cspm\real_time_monitoring\aws\terraform\modules\s3\config_files'
    
    files_to_update = {
        's3/s3_bucket_acl.rego': os.path.join(base_path, 's3', 's3_bucket_acl.rego'),
        's3/s3_kms_audit.rego': os.path.join(base_path, 's3', 's3_kms_audit.rego'),
        'kms/kms_key_audit.rego': os.path.join(base_path, 'kms', 'kms_key_audit.rego'),
    }
    
    commands = []
    
    # Construct commands to overwrite files on EC2
    for remote_path, local_path in files_to_update.items():
        with open(local_path, 'r') as f:
            content = f.read()
            # Escape single quotes for bash
            content = content.replace("'", "'\\''")
            
            cmd = f"cat << 'EOF' > /home/ec2-user/config_files/{remote_path}\n{content}\nEOF"
            commands.append(cmd)
            
    # Add restart command
    # Kill existing OPA
    commands.append("pkill opa")
    # Wait a sec
    commands.append("sleep 2")
    # Start OPA again (using the same command as user_data)
    commands.append("nohup sudo -u ec2-user /home/ec2-user/opa run --server /home/ec2-user/config_files --addr 0.0.0.0:8181 > /var/log/opa.log 2>&1 &")
    
    print(f"Sending Update & Restart command to instance {instance_id}...")
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
        )
        
        command_id = response['Command']['CommandId']
        print(f"Command sent! ID: {command_id}")
        
        # Poll for status
        for i in range(15):
            time.sleep(2)
            output = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = output['Status']
            print(f"Status: {status}")
            
            if status in ['Success', 'Failed', 'Cancelled']:
                print("\n--- Command Output ---")
                print(output['StandardOutputContent'])
                if output['StandardErrorContent']:
                    print("\n--- Command Error ---")
                    print(output['StandardErrorContent'])
                break
                
    except Exception as e:
        print(f"Error running SSM command: {e}")

if __name__ == "__main__":
    instance_id = 'i-052a3b6b8972946f8'
    if len(sys.argv) > 1:
        instance_id = sys.argv[1]
        
    update_opa_config(instance_id)
