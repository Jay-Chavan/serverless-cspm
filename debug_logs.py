import boto3
import time
from datetime import datetime, timedelta

def get_recent_logs(log_group_name='/aws/lambda/cspm-s3-auditor', minutes=10):
    client = boto3.client('logs', region_name='ap-south-1')
    
    print(f"Fetching logs from {log_group_name} for the last {minutes} minutes...")
    
    try:
        # Get the latest log stream
        streams = client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=5
        )
        
        if not streams.get('logStreams'):
            print("No log streams found.")
            return

        for stream in streams['logStreams']:
            stream_name = stream['logStreamName']
            print(f"\n--- Log Stream: {stream_name} ---")
            
            # Get log events
            response = client.get_log_events(
                logGroupName=log_group_name,
                logStreamName=stream_name,
                startTime=int((datetime.now() - timedelta(minutes=minutes)).timestamp() * 1000),
                limit=20,
                startFromHead=False
            )
            
            events = response.get('events', [])
            if not events:
                print("No recent events in this stream.")
                continue
                
            for event in events:
                timestamp = datetime.fromtimestamp(event['timestamp'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                message = event['message'].strip()
                print(f"[{timestamp}] {message}")

    except Exception as e:
        print(f"Error fetching logs: {e}")

if __name__ == "__main__":
    get_recent_logs()
