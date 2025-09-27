# MongoDB Atlas Configuration for CSPM KMS Audit

## Overview
This guide explains how to configure MongoDB Atlas for the CSPM KMS security audit system.

## Prerequisites
1. MongoDB Atlas account
2. Atlas cluster created
3. Database user with read/write permissions
4. Network access configured (IP whitelist or 0.0.0.0/0 for development)

## Environment Variables Setup

### Required Environment Variables

```bash
# MongoDB Atlas connection string
MONGODB_CONNECTION_STRING="mongodb+srv://<username>:<password>@<cluster>.mongodb.net/"

# Database and collection names (optional, defaults provided)
MONGODB_DATABASE="cspm_findings"
MONGODB_COLLECTION="kms_security_findings"
```

### Getting Your Connection String

1. **Login to MongoDB Atlas**
   - Go to https://cloud.mongodb.com/
   - Login to your account

2. **Navigate to Your Cluster**
   - Select your project
   - Click on your cluster name

3. **Get Connection String**
   - Click "Connect" button
   - Choose "Connect your application"
   - Select "Python" and version "3.6 or later"
   - Copy the connection string

4. **Replace Placeholders**
   ```
   Original: mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/
   Replace:  mongodb+srv://myuser:mypassword@cluster0.xxxxx.mongodb.net/
   ```

## Setting Environment Variables

### For Local Development (Windows)
```powershell
# Set environment variables in PowerShell
$env:MONGODB_CONNECTION_STRING="mongodb+srv://myuser:mypassword@cluster0.xxxxx.mongodb.net/"
$env:MONGODB_DATABASE="cspm_findings"
$env:MONGODB_COLLECTION="kms_security_findings"
```

### For AWS Lambda Deployment
1. **Lambda Environment Variables**
   - Go to AWS Lambda Console
   - Select your function
   - Go to Configuration → Environment variables
   - Add the variables:
     - `MONGODB_CONNECTION_STRING`: Your Atlas connection string
     - `MONGODB_DATABASE`: cspm_findings
     - `MONGODB_COLLECTION`: kms_security_findings

2. **Using AWS Systems Manager Parameter Store (Recommended)**
   ```python
   import boto3
   
   def get_mongodb_connection_string():
       ssm = boto3.client('ssm')
       parameter = ssm.get_parameter(
           Name='/cspm/mongodb/connection_string',
           WithDecryption=True
       )
       return parameter['Parameter']['Value']
   ```

### For EC2 Deployment
```bash
# Add to /etc/environment or ~/.bashrc
export MONGODB_CONNECTION_STRING="mongodb+srv://myuser:mypassword@cluster0.xxxxx.mongodb.net/"
export MONGODB_DATABASE="cspm_findings"
export MONGODB_COLLECTION="kms_security_findings"
```

## Security Best Practices

### 1. Database User Permissions
Create a dedicated user with minimal required permissions:
```javascript
// In MongoDB Atlas, create user with these roles:
{
  "roles": [
    {
      "role": "readWrite",
      "db": "cspm_findings"
    }
  ]
}
```

### 2. Network Security
- **Development**: Allow access from your IP
- **Production**: Use VPC peering or private endpoints
- **Lambda**: Configure VPC if needed, or use 0.0.0.0/0 with strong authentication

### 3. Connection String Security
- **Never hardcode** connection strings in code
- Use environment variables or parameter stores
- Rotate passwords regularly
- Use strong passwords (Atlas can generate them)

## Database Schema

The system will automatically create the following structure:

```javascript
// Database: cspm_findings
// Collection: kms_security_findings

// Document structure:
{
  "_id": ObjectId("..."),
  "finding_id": "abc123...",
  "resource_type": "kms",
  "resource_id": "arn:aws:kms:region:account:key/key-id",
  "account_id": "123456789012",
  "region": "us-east-1",
  "risk_level": "Critical",
  "reason": "KMS key allows public access",
  "raw_opa_response": {...},
  "metadata": {
    "created_at": ISODate("2024-01-15T10:30:00Z"),
    "source": "cspm-kms-audit",
    "version": "1.0"
  }
}
```

## Testing Connection

Use this script to test your MongoDB Atlas connection:

```python
import os
from pymongo import MongoClient

def test_mongodb_connection():
    try:
        connection_string = os.environ.get('MONGODB_CONNECTION_STRING')
        if not connection_string:
            print("❌ MONGODB_CONNECTION_STRING not set")
            return False
            
        client = MongoClient(connection_string)
        client.server_info()  # Test connection
        print("✅ MongoDB Atlas connection successful")
        
        # Test database access
        db = client[os.environ.get('MONGODB_DATABASE', 'cspm_findings')]
        collection = db[os.environ.get('MONGODB_COLLECTION', 'kms_security_findings')]
        
        # Insert test document
        test_doc = {"test": True, "timestamp": "2024-01-15T10:30:00Z"}
        result = collection.insert_one(test_doc)
        print(f"✅ Test document inserted: {result.inserted_id}")
        
        # Clean up test document
        collection.delete_one({"_id": result.inserted_id})
        print("✅ Test document cleaned up")
        
        return True
        
    except Exception as e:
        print(f"❌ MongoDB Atlas connection failed: {e}")
        return False

if __name__ == "__main__":
    test_mongodb_connection()
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Check username/password in connection string
   - Verify user exists and has correct permissions

2. **Network Timeout**
   - Check IP whitelist in Atlas
   - Verify network connectivity
   - Check firewall settings

3. **SSL/TLS Issues**
   - Atlas requires SSL by default
   - Ensure `ssl=True` in connection parameters

4. **Connection String Format**
   - Use `mongodb+srv://` for Atlas (not `mongodb://`)
   - Ensure no spaces or special characters are URL-encoded

### Debug Mode
Set this environment variable for detailed connection logging:
```bash
export MONGODB_DEBUG=true
```

## Support
- MongoDB Atlas Documentation: https://docs.atlas.mongodb.com/
- PyMongo Documentation: https://pymongo.readthedocs.io/