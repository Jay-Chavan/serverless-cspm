"""
KMS Lambda Handler for CSPM Real-time Monitoring
Provides API endpoints for KMS key security auditing
"""

import json
import os
import sys
import boto3
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import the existing KMS audit functionality
from KMSAudit import audit_kms_key_security, get_kms_key_security_config

class KMSLambdaHandler:
    """Main handler for KMS auditing Lambda function"""
    
    def __init__(self):
        """Initialize the KMS Lambda handler"""
        # Initialize AWS clients
        self.kms_client = boto3.client('kms')
        self.security_hub_client = boto3.client('securityhub')
        
        # MongoDB configuration (if needed)
        self.mongo_uri = os.environ.get('MONGODB_URI')
        self.mongo_db = os.environ.get('MONGODB_DATABASE', 'cspm')
        self.mongo_collection = os.environ.get('MONGODB_COLLECTION', 'kms_audit_results')
        
        # OPA configuration
        self.opa_url = os.environ.get('OPA_URL', 'http://localhost:8181')
        
        print("KMS Lambda Handler initialized successfully")
    
    def lambda_handler(self, event, context):
        """
        Main Lambda handler function
        
        Args:
            event: Lambda event data
            context: Lambda context object
            
        Returns:
            Dict containing response data
        """
        try:
            print(f"KMS Lambda handler invoked with event: {json.dumps(event, default=str)}")
            
            # Handle different event sources
            if 'httpMethod' in event:
                # API Gateway event
                return self._handle_api_gateway_event(event, context)
            else:
                # Direct Lambda invocation
                return self._handle_direct_invocation(event, context)
                
        except Exception as e:
            error_msg = f"KMS Lambda handler error: {str(e)}"
            print(f"ERROR: {error_msg}")
            
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': error_msg,
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
    
    def _handle_api_gateway_event(self, event, context):
        """Handle API Gateway events"""
        try:
            method = event.get('httpMethod', 'GET')
            path = event.get('path', '/')
            
            # Parse request body if present
            body = {}
            if event.get('body'):
                try:
                    body = json.loads(event['body'])
                except json.JSONDecodeError:
                    return {
                        'statusCode': 400,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({'error': 'Invalid JSON in request body'})
                    }
            
            # Route to appropriate handler
            if method == 'POST' and path == '/audit-key':
                return self._handle_audit_key(body)
            elif method == 'POST' and path == '/audit-multiple':
                return self._handle_audit_multiple_keys(body)
            elif method == 'POST' and path == '/key-info':
                return self._handle_get_key_info(body)
            elif method == 'GET' and path == '/health':
                return self._handle_health_check()
            else:
                return {
                    'statusCode': 404,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Endpoint not found'})
                }
                
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': str(e)})
            }
    
    def _handle_direct_invocation(self, event, context):
        """Handle direct Lambda invocation"""
        try:
            action = event.get('action', 'audit_key')
            
            if action == 'audit_key':
                key_id = event.get('key_id')
                if not key_id:
                    raise ValueError("key_id is required for audit_key action")
                
                result = self.audit_kms_key(
                    key_id, 
                    event.get('account_id'),
                    event.get('region'),
                    event.get('additional_params', {})
                )
                
                return {
                    'statusCode': 200,
                    'result': result
                }
            
            elif action == 'audit_multiple_keys':
                key_ids = event.get('key_ids', [])
                if not key_ids:
                    raise ValueError("key_ids list is required for audit_multiple_keys action")
                
                result = self.audit_multiple_keys(
                    key_ids,
                    event.get('account_id'),
                    event.get('region')
                )
                
                return {
                    'statusCode': 200,
                    'result': result
                }
            
            elif action == 'get_key_info':
                key_id = event.get('key_id')
                if not key_id:
                    raise ValueError("key_id is required for get_key_info action")
                
                result = self.get_key_info(
                    key_id,
                    event.get('region')
                )
                
                return {
                    'statusCode': 200,
                    'result': result
                }
            
            elif action == 'health_check':
                return {
                    'statusCode': 200,
                    'result': {
                        'status': 'healthy',
                        'service': 'KMS CSPM Auditor',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                }
            
            else:
                raise ValueError(f"Unknown action: {action}")
                
        except Exception as e:
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _handle_audit_key(self, body):
        """Handle single key audit request"""
        try:
            key_id = body.get('key_id')
            if not key_id:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'key_id is required'})
                }
            
            result = self.audit_kms_key(
                key_id,
                body.get('account_id'),
                body.get('region'),
                body.get('additional_params', {})
            )
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }
            
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': str(e)})
            }
    
    def _handle_audit_multiple_keys(self, body):
        """Handle multiple keys audit request"""
        try:
            key_ids = body.get('key_ids', [])
            if not key_ids:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'key_ids list is required'})
                }
            
            result = self.audit_multiple_keys(
                key_ids,
                body.get('account_id'),
                body.get('region')
            )
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }
            
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': str(e)})
            }
    
    def _handle_get_key_info(self, body):
        """Handle get key info request"""
        try:
            key_id = body.get('key_id')
            if not key_id:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'key_id is required'})
                }
            
            result = self.get_key_info(
                key_id,
                body.get('region')
            )
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }
            
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': str(e)})
            }
    
    def _handle_health_check(self):
        """Handle health check request"""
        try:
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'status': 'healthy',
                    'service': 'KMS CSPM Auditor',
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': str(e)})
            }
    
    def audit_kms_key(self, key_id: str, account_id: str = None, region: str = None, additional_params: Dict = None) -> Dict[str, Any]:
        """
        Audit a single KMS key
        
        Args:
            key_id: KMS key ID or ARN
            account_id: AWS account ID (optional, will be detected if not provided)
            region: AWS region (optional, will use current region if not provided)
            additional_params: Additional parameters for the audit
            
        Returns:
            Dict containing audit results
        """
        try:
            print(f"Starting KMS audit for key: {key_id}")
            
            # Get account ID if not provided
            if not account_id:
                account_id = boto3.client('sts').get_caller_identity()['Account']
            
            # Get region if not provided
            if not region:
                region = os.environ.get('AWS_REGION', 'us-east-1')
            
            # Perform the audit using existing function
            audit_result = audit_kms_key_security(key_id, account_id, region, self.kms_client)
            
            # Enhance the result with additional metadata
            enhanced_result = {
                'key_id': key_id,
                'account_id': account_id,
                'region': region,
                'timestamp': datetime.utcnow().isoformat(),
                'audit_results': audit_result,
                'status': 'completed' if audit_result else 'no_findings'
            }
            
            # Store in MongoDB if configured
            try:
                self._store_in_mongodb(enhanced_result)
            except Exception as e:
                print(f"WARNING: Failed to store in MongoDB: {e}")
            
            print(f"KMS audit completed for key: {key_id}")
            return enhanced_result
            
        except Exception as e:
            error_msg = f"KMS audit failed for key {key_id}: {str(e)}"
            print(f"ERROR: {error_msg}")
            
            return {
                'key_id': key_id,
                'error': error_msg,
                'status': 'failed',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def audit_multiple_keys(self, key_ids: List[str], account_id: str = None, region: str = None) -> Dict[str, Any]:
        """
        Audit multiple KMS keys
        
        Args:
            key_ids: List of KMS key IDs or ARNs
            account_id: AWS account ID (optional)
            region: AWS region (optional)
            
        Returns:
            Dict containing audit results for all keys
        """
        try:
            print(f"Starting KMS audit for {len(key_ids)} keys")
            
            results = {
                'total_keys': len(key_ids),
                'successful_audits': 0,
                'failed_audits': 0,
                'audit_results': {},
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed'
            }
            
            for key_id in key_ids:
                try:
                    audit_result = self.audit_kms_key(key_id, account_id, region)
                    results['audit_results'][key_id] = audit_result
                    
                    if audit_result.get('status') == 'failed':
                        results['failed_audits'] += 1
                    else:
                        results['successful_audits'] += 1
                        
                except Exception as e:
                    print(f"ERROR: Failed to audit key {key_id}: {e}")
                    results['audit_results'][key_id] = {
                        'key_id': key_id,
                        'error': str(e),
                        'status': 'failed'
                    }
                    results['failed_audits'] += 1
            
            print(f"Multiple KMS audit completed: {results['successful_audits']} successful, {results['failed_audits']} failed")
            return results
            
        except Exception as e:
            return {
                'error': f"Multiple KMS audit failed: {str(e)}",
                'status': 'failed',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_key_info(self, key_id: str, region: str = None) -> Dict[str, Any]:
        """
        Get basic KMS key information (lightweight call)
        
        Args:
            key_id: KMS key ID or ARN
            region: AWS region (optional)
            
        Returns:
            Dict containing key information
        """
        try:
            print(f"Getting KMS key info for: {key_id}")
            
            # Get region if not provided
            if not region:
                region = os.environ.get('AWS_REGION', 'us-east-1')
            
            # Get key configuration using existing function
            key_config = get_kms_key_security_config(key_id, self.kms_client)
            
            # Return lightweight key information
            key_info = {
                'key_id': key_id,
                'key_arn': key_config.get('key_arn'),
                'key_state': key_config.get('key_state'),
                'key_usage': key_config.get('key_usage'),
                'key_spec': key_config.get('key_spec'),
                'origin': key_config.get('origin'),
                'key_manager': key_config.get('key_manager'),
                'key_rotation_enabled': key_config.get('key_rotation_enabled', False),
                'aliases': key_config.get('aliases', []),
                'region': region,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'success'
            }
            
            print(f"KMS key info retrieved for: {key_id}")
            return key_info
            
        except Exception as e:
            error_msg = f"Failed to get KMS key info for {key_id}: {str(e)}"
            print(f"ERROR: {error_msg}")
            
            return {
                'key_id': key_id,
                'error': error_msg,
                'status': 'failed',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _store_in_mongodb(self, audit_result: Dict):
        """
        Store audit results in MongoDB
        
        Args:
            audit_result: Audit result data
        """
        try:
            if self.mongo_uri:
                from pymongo import MongoClient
                
                client = MongoClient(self.mongo_uri)
                db = client[self.mongo_db]
                collection = db[self.mongo_collection]
                
                # Add MongoDB document metadata
                audit_result['_id'] = f"{audit_result['key_id']}_{audit_result['timestamp']}"
                audit_result['created_at'] = datetime.utcnow()
                
                collection.insert_one(audit_result)
                print(f"Stored KMS audit results in MongoDB for key: {audit_result['key_id']}")
                
                client.close()
        except Exception as e:
            print(f"WARNING: Failed to store results in MongoDB: {e}")

# Lambda handler function
def lambda_handler(event, context):
    """
    AWS Lambda entry point
    
    Args:
        event: Lambda event data
        context: Lambda context object
        
    Returns:
        Response data
    """
    handler = KMSLambdaHandler()
    return handler.lambda_handler(event, context)