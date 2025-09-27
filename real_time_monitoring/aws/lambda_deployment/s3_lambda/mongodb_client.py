import pymongo
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError
import sys

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
        
    def connect(self, database_name='csmp_findings', collection_name='s3_audit_findings'):
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
            print(f"[DEBUG] Python version: {sys.version}")
            print(f"[DEBUG] PyMongo version: {pymongo.version}")
            
            # Create MongoDB client with explicit parameters for better compatibility
            self.client = pymongo.MongoClient(
                self.connection_string,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=5000
            )
            
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
            print(f"[ERROR] Exception type: {type(e).__name__}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
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
                    
                    # Safely extract region from Resources
                    region = None
                    resources = finding.get('Resources', [])
                    if resources and len(resources) > 0 and isinstance(resources[0], dict):
                        region = resources[0].get('Region')
                    
                    document.update({
                        'finding_id': finding.get('Id'),
                        'severity': finding.get('Severity', {}).get('Label'),
                        'title': finding.get('Title'),
                        'description': finding.get('Description'),
                        'aws_account_id': finding.get('AwsAccountId'),
                        'region': region,
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
    try:
        print("[INFO] Initializing MongoDB client...")
        mongo_client = MongoDBClient()
        
        print("[INFO] Attempting to connect to MongoDB...")
        if mongo_client.connect():
            print("[INFO] MongoDB connection successful, storing finding...")
            document_id = mongo_client.store_finding(finding_data, bucket_name)
            mongo_client.close_connection()
            return document_id
        else:
            print("[ERROR] Failed to connect to MongoDB for storing finding")
            return None
    except Exception as e:
        print(f"[ERROR] Exception in store_finding_to_mongodb: {str(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None