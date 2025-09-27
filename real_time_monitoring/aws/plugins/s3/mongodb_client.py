import pymongo
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

class MongoDBClient:
    """
    MongoDB client for storing CSPM findings
    """
    
    def __init__(self, connection_string=None):
        """
        Initialize MongoDB client with connection string
        
        Args:
            connection_string: MongoDB connection string. If None, uses environment variable.
        """
        self.connection_string = connection_string or os.environ.get(
            'MONGODB_CONNECTION_STRING',
            'mongodb+srv://1032221163:WmG3kLX4WIv8GEJk@cluster0.4kypzkq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
        )
        self.client = None
        self.db = None
        self.collection = None
        
    def connect(self, database_name='cspm_findings', collection_name='s3_audit_findings'):
        """
        Connect to MongoDB cluster and select database/collection
        
        Args:
            database_name: Name of the database to use
            collection_name: Name of the collection to use
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            print(f"[INFO] Connecting to MongoDB cluster...")
            self.client = pymongo.MongoClient(self.connection_string)
            
            # Test the connection
            self.client.admin.command('ping')
            print(f"[INFO] Successfully connected to MongoDB cluster")
            
            # Select database and collection
            self.db = self.client[database_name]
            self.collection = self.db[collection_name]
            
            print(f"[INFO] Using database: {database_name}, collection: {collection_name}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to connect to MongoDB: {str(e)}")
            return False
    
    def store_finding(self, finding_data, bucket_name=None):
        """
        Store a security finding in MongoDB
        
        Args:
            finding_data: The finding data (dict or Security Hub finding format)
            bucket_name: Optional bucket name for additional metadata
            
        Returns:
            str: Document ID if successful, None if failed
        """
        try:
            if self.collection is None:
                print("[ERROR] MongoDB collection not initialized. Call connect() first.")
                return None
            
            # Prepare document for storage
            document = {
                'timestamp': datetime.now(timezone.utc),
                'bucket_name': bucket_name,
                'finding_data': finding_data,
                'source': 'cspm-s3-auditor'
            }
            
            # If finding_data is in Security Hub format, extract key information
            if isinstance(finding_data, dict) and 'Findings' in finding_data:
                findings = finding_data['Findings']
                if findings and len(findings) > 0:
                    finding = findings[0]
                    document.update({
                        'finding_id': finding.get('Id'),
                        'severity': finding.get('Severity', {}).get('Label'),
                        'title': finding.get('Title'),
                        'description': finding.get('Description'),
                        'aws_account_id': finding.get('AwsAccountId'),
                        'region': finding.get('Resources', [{}])[0].get('Region') if finding.get('Resources') else None,
                        'compliance_status': finding.get('Compliance', {}).get('Status'),
                        'workflow_state': finding.get('WorkflowState'),
                        'record_state': finding.get('RecordState')
                    })
            
            # Insert document
            result = self.collection.insert_one(document)
            document_id = str(result.inserted_id)
            
            print(f"[INFO] Successfully stored finding in MongoDB with ID: {document_id}")
            return document_id
            
        except Exception as e:
            print(f"[ERROR] Failed to store finding in MongoDB: {str(e)}")
            return None
    
    def get_findings_by_bucket(self, bucket_name, limit=10):
        """
        Retrieve findings for a specific bucket
        
        Args:
            bucket_name: Name of the S3 bucket
            limit: Maximum number of findings to return
            
        Returns:
            list: List of findings or empty list if none found
        """
        try:
            if self.collection is None:
                print("[ERROR] MongoDB collection not initialized. Call connect() first.")
                return []
            
            findings = list(self.collection.find(
                {'bucket_name': bucket_name}
            ).sort('timestamp', -1).limit(limit))
            
            # Convert ObjectId to string for JSON serialization
            for finding in findings:
                finding['_id'] = str(finding['_id'])
                if 'timestamp' in finding:
                    finding['timestamp'] = finding['timestamp'].isoformat()
            
            print(f"[INFO] Retrieved {len(findings)} findings for bucket: {bucket_name}")
            return findings
            
        except Exception as e:
            print(f"[ERROR] Failed to retrieve findings from MongoDB: {str(e)}")
            return []
    
    def get_recent_findings(self, limit=50):
        """
        Retrieve recent findings across all buckets
        
        Args:
            limit: Maximum number of findings to return
            
        Returns:
            list: List of recent findings
        """
        try:
            if self.collection is None:
                print("[ERROR] MongoDB collection not initialized. Call connect() first.")
                return []
            
            findings = list(self.collection.find().sort('timestamp', -1).limit(limit))
            
            # Convert ObjectId to string for JSON serialization
            for finding in findings:
                finding['_id'] = str(finding['_id'])
                if 'timestamp' in finding:
                    finding['timestamp'] = finding['timestamp'].isoformat()
            
            print(f"[INFO] Retrieved {len(findings)} recent findings")
            return findings
            
        except Exception as e:
            print(f"[ERROR] Failed to retrieve recent findings from MongoDB: {str(e)}")
            return []
    
    def close_connection(self):
        """
        Close MongoDB connection
        """
        try:
            if self.client:
                self.client.close()
                print("[INFO] MongoDB connection closed")
        except Exception as e:
            print(f"[ERROR] Error closing MongoDB connection: {str(e)}")

# Convenience function for Lambda usage
def store_finding_to_mongodb(finding_data, bucket_name=None):
    """
    Convenience function to store a finding in MongoDB
    
    Args:
        finding_data: The finding data to store
        bucket_name: Optional bucket name
        
    Returns:
        str: Document ID if successful, None if failed
    """
    mongo_client = MongoDBClient()
    
    if mongo_client.connect():
        document_id = mongo_client.store_finding(finding_data, bucket_name)
        mongo_client.close_connection()
        return document_id
    else:
        print("[ERROR] Failed to connect to MongoDB for storing finding")
        return None