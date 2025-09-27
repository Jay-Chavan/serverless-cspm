#!/usr/bin/env python3
"""
Test script for MongoDB Atlas connection.
Run this script to verify your Atlas configuration is working correctly.
"""

import os
import sys
from datetime import datetime
from pymongo import MongoClient

def test_mongodb_atlas_connection():
    """Test MongoDB Atlas connection and basic operations."""
    
    print("🔍 Testing MongoDB Atlas Connection...")
    print("=" * 50)
    
    # Check environment variables
    connection_string = os.environ.get('MONGODB_CONNECTION_STRING')
    database_name = os.environ.get('MONGODB_DATABASE', 'cspm_findings')
    collection_name = os.environ.get('MONGODB_COLLECTION', 'kms_security_findings')
    
    print(f"📋 Configuration:")
    print(f"   Database: {database_name}")
    print(f"   Collection: {collection_name}")
    print(f"   Connection String: {'✅ Set' if connection_string else '❌ Not Set'}")
    
    if not connection_string:
        print("\n❌ MONGODB_CONNECTION_STRING environment variable not set!")
        print("Please set it using:")
        print('   $env:MONGODB_CONNECTION_STRING="mongodb+srv://user:pass@cluster.mongodb.net/"')
        return False
    
    if '<username>' in connection_string or '<password>' in connection_string:
        print("\n❌ Connection string contains placeholder values!")
        print("Please replace <username> and <password> with actual credentials.")
        return False
    
    try:
        print(f"\n🔌 Connecting to MongoDB Atlas...")
        
        # Create client with Atlas-optimized settings
        client = MongoClient(
            connection_string,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=20000,
            socketTimeoutMS=20000,
            ssl=True,
            retryWrites=True,
            w='majority'
        )
        
        # Test connection
        server_info = client.server_info()
        print(f"✅ Connected successfully!")
        print(f"   MongoDB Version: {server_info.get('version', 'Unknown')}")
        
        # Test database access
        db = client[database_name]
        collection = db[collection_name]
        
        print(f"\n📊 Testing database operations...")
        
        # Test write operation
        test_document = {
            "test_id": "connection_test",
            "timestamp": datetime.utcnow().isoformat(),
            "test_data": {
                "resource_type": "test",
                "status": "connection_successful"
            }
        }
        
        result = collection.insert_one(test_document)
        print(f"✅ Write test successful - Document ID: {result.inserted_id}")
        
        # Test read operation
        found_doc = collection.find_one({"_id": result.inserted_id})
        if found_doc:
            print(f"✅ Read test successful - Found document")
        else:
            print(f"❌ Read test failed - Document not found")
            return False
        
        # Test update operation
        update_result = collection.update_one(
            {"_id": result.inserted_id},
            {"$set": {"test_updated": True}}
        )
        print(f"✅ Update test successful - Modified: {update_result.modified_count}")
        
        # Clean up test document
        delete_result = collection.delete_one({"_id": result.inserted_id})
        print(f"✅ Cleanup successful - Deleted: {delete_result.deleted_count}")
        
        # Test collection stats
        try:
            stats = db.command("collStats", collection_name)
            doc_count = stats.get('count', 0)
            print(f"\n📈 Collection Statistics:")
            print(f"   Document Count: {doc_count}")
            print(f"   Storage Size: {stats.get('storageSize', 0)} bytes")
        except Exception as e:
            print(f"⚠️  Could not get collection stats: {e}")
        
        print(f"\n🎉 All tests passed! MongoDB Atlas is ready for CSPM.")
        return True
        
    except Exception as e:
        print(f"\n❌ Connection test failed!")
        print(f"Error: {e}")
        print(f"\n🔧 Troubleshooting tips:")
        print(f"   1. Check your connection string format")
        print(f"   2. Verify username/password are correct")
        print(f"   3. Ensure IP address is whitelisted in Atlas")
        print(f"   4. Check network connectivity")
        return False
    
    finally:
        try:
            if 'client' in locals():
                client.close()
                print(f"🔌 Connection closed.")
        except:
            pass

def main():
    """Main function to run the test."""
    print("MongoDB Atlas Connection Test for CSPM")
    print("=" * 50)
    
    success = test_mongodb_atlas_connection()
    
    if success:
        print(f"\n✅ SUCCESS: MongoDB Atlas is properly configured!")
        sys.exit(0)
    else:
        print(f"\n❌ FAILED: Please check your MongoDB Atlas configuration.")
        sys.exit(1)

if __name__ == "__main__":
    main()