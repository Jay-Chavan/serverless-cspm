import requests
from typing import Dict, Any, Optional
from pymongo import MongoClient
from datetime import datetime
import json
import os

# --- Configuration ---
KMS_OPA_URL = "http://172.20.45.17:8181/v1/data/aws/kms_key/deny"

# MongoDB Atlas Configuration
MONGODB_CONFIG = {
    # MongoDB Atlas connection string (set via environment variable for security)
    "connection_string": os.environ.get('MONGODB_CONNECTION_STRING', 
                                       'mongodb+srv://<username>:<password>@<cluster>.mongodb.net/'),
    "database": os.environ.get('MONGODB_DATABASE', 'cspm_findings'),
    "collection": os.environ.get('MONGODB_COLLECTION', 'kms_security_findings'),
    
    # Atlas-specific settings
    "ssl": True,
    "ssl_cert_reqs": "CERT_NONE",  # For Atlas, certificates are handled automatically
    "retryWrites": True,
    "w": "majority"
}

class MongoDBClient:
    """MongoDB client for storing security findings."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.db = None
        self.collection = None
        self._connect()
    
    def _connect(self):
        """Establish connection to MongoDB Atlas with retry logic."""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Use Atlas connection string
                connection_string = self.config['connection_string']
                
                # Validate connection string
                if '<username>' in connection_string or '<password>' in connection_string:
                    raise ValueError("MongoDB connection string contains placeholder values. Please set MONGODB_CONNECTION_STRING environment variable.")
                
                self.client = MongoClient(
                    connection_string,
                    serverSelectionTimeoutMS=10000,
                    connectTimeoutMS=20000,
                    socketTimeoutMS=20000,
                    ssl=self.config.get('ssl', True),
                    retryWrites=self.config.get('retryWrites', True),
                    w=self.config.get('w', 'majority')
                )
                
                # Test connection
                self.client.server_info()
                self.db = self.client[self.config['database']]
                self.collection = self.db[self.config['collection']]
                print(f"[INFO] Connected to MongoDB Atlas: {self.config['database']}.{self.config['collection']}")
                return
                
            except Exception as e:
                retry_count += 1
                print(f"[WARNING] MongoDB connection attempt {retry_count} failed: {e}")
                if retry_count >= max_retries:
                    print(f"[ERROR] Failed to connect to MongoDB after {max_retries} attempts")
                    self.client = None
                else:
                    import time
                    time.sleep(2)  # Wait 2 seconds before retry
    
    def push_finding(self, finding_data: Dict[str, Any]) -> bool:
        """
        Push a security finding to MongoDB with validation and error handling.
        
        Args:
            finding_data: Dictionary containing the finding details
            
        Returns:
            True if successful, False otherwise
        """
        if not self.client or not self.collection:
            print("[ERROR] MongoDB connection not available")
            return False
        
        # Validate required fields
        required_fields = ["resource_type", "risk_level", "reason"]
        for field in required_fields:
            if field not in finding_data:
                print(f"[ERROR] Missing required field '{field}' in finding data")
                return False
        
        try:
            # Sanitize and prepare document
            finding_document = {
                "resource_type": str(finding_data.get("resource_type", "")),
                "risk_level": str(finding_data.get("risk_level", "")),
                "reason": str(finding_data.get("reason", "")),
                "timestamp": datetime.utcnow(),
                "source": "kms_opa_audit",
                "version": "1.0",
                "raw_opa_response": finding_data.get("raw_opa_response", {}),
                "kms_config": finding_data.get("kms_config", {}),
                "metadata": {
                    "audit_timestamp": datetime.utcnow().isoformat(),
                    "finding_id": f"kms_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(finding_data)) % 10000:04d}"
                }
            }
            
            # Insert with retry logic
            max_retries = 2
            for attempt in range(max_retries + 1):
                try:
                    result = self.collection.insert_one(finding_document)
                    print(f"[INFO] Finding pushed to MongoDB with ID: {result.inserted_id}")
                    return True
                except Exception as retry_error:
                    if attempt < max_retries:
                        print(f"[WARNING] Insert attempt {attempt + 1} failed, retrying: {retry_error}")
                        import time
                        time.sleep(1)
                    else:
                        raise retry_error
            
        except Exception as e:
            print(f"[ERROR] Failed to push finding to MongoDB: {e}")
            # Try to reconnect for next time
            try:
                self._connect()
            except:
                pass
            return False
    
    def close(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            print("[INFO] MongoDB connection closed")

# Initialize MongoDB client
mongo_client = MongoDBClient(MONGODB_CONFIG)

def send_kms_opa_request(kms_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sends a request to OPA with the KMS key configuration and returns the response.
    
    Args:
        kms_config: Dictionary containing KMS key security configuration
        
    Returns:
        OPA response data or None if request fails
    """
    input_data = {
        "input": {
            "resource_type": "kms",
            "kms_config": kms_config
        }
    }
    
    try:
        print("[DEBUG] Preparing to query KMS OPA...")
        print(f"[DEBUG] >> KMS OPA URL: {KMS_OPA_URL}")
        print(f"[DEBUG] >> KMS OPA Input Payload: {input_data}")
        
        opa_response = requests.post(
            url=KMS_OPA_URL,
            json=input_data,
            timeout=10
        )

        print(f"[DEBUG] >> KMS OPA Response Status Code: {opa_response.status_code}")
        print(f"[DEBUG] >> KMS OPA Raw Response Text: {opa_response.text}")
        
        opa_response.raise_for_status()
        response_data = opa_response.json()
        return response_data
        
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] KMS OPA request failed. Reason: {e}")
        return None
    except requests.exceptions.JSONDecodeError as e:
        print(f"[ERROR] Could not decode JSON from KMS OPA response. Reason: {e}")
        return None

def parse_kms_opa_response(response_data: Dict[str, Any], kms_config: Dict[str, Any] = None) -> Optional[Dict[str, str]]:
    """
    Parses KMS OPA response and extracts finding details.
    
    Args:
        response_data: Raw KMS OPA response data
        kms_config: Original KMS configuration for context (optional)
        
    Returns:
        Dictionary with risk_level and reason, or None if no findings
    """
    print("[DEBUG] Parsing KMS OPA response...")
    result = response_data.get("result", [])
    print(f"[DEBUG] >> Parsed KMS 'result' field: {result}")

    if not result or not isinstance(result, list):
        print("[INFO] No KMS findings from OPA. KMS key is compliant.")
        return None
    
    finding_details = result[0]
    risk = finding_details.get("risk_level", "High")
    reason = finding_details.get("reason", "No reason provided.")
    print(f"[DEBUG] >> Extracted KMS Risk='{risk}', Reason='{reason}'")
    
    # Handle specific OPA results
    if "Unrecognized" in risk:
        risk = "Critical"
    
    # Prepare finding data for MongoDB
    finding_data = {
        "resource_type": "kms",
        "risk_level": risk,
        "reason": reason,
        "raw_opa_response": response_data,
        "kms_config": kms_config or {}
    }
    
    # Push finding to MongoDB
    try:
        success = mongo_client.push_finding(finding_data)
        if success:
            print(f"[INFO] KMS finding successfully stored in MongoDB")
        else:
            print(f"[WARNING] Failed to store KMS finding in MongoDB")
    except Exception as e:
        print(f"[ERROR] Exception while pushing KMS finding to MongoDB: {e}")
        
    return {
        "risk_level": risk,
        "reason": reason
    }

def audit_kms_key(kms_config: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Complete KMS key audit workflow: send to OPA, parse response, and store findings.
    
    Args:
        kms_config: Dictionary containing KMS key security configuration
        
    Returns:
        Dictionary with risk_level and reason, or None if no findings
    """
    print("[INFO] Starting KMS key audit workflow...")
    
    # Send request to OPA
    opa_response = send_kms_opa_request(kms_config)
    if not opa_response:
        print("[ERROR] Failed to get response from KMS OPA")
        return None
    
    # Parse response and store findings
    finding = parse_kms_opa_response(opa_response, kms_config)
    
    if finding:
        print(f"[INFO] KMS audit completed. Finding: {finding['risk_level']} - {finding['reason']}")
    else:
        print("[INFO] KMS audit completed. No security issues found.")
    
    return finding

def close_mongodb_connection():
    """Close the MongoDB connection gracefully."""
    try:
        mongo_client.close()
    except Exception as e:
        print(f"[ERROR] Error closing MongoDB connection: {e}")

# Ensure MongoDB connection is closed on module cleanup
import atexit
atexit.register(close_mongodb_connection)