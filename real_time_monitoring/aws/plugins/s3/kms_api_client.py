"""
KMS API Client for S3 Plugins
Handles communication with the KMS Lambda function for KMS key auditing
"""

import json
import os
import boto3
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any

class KMSAPIClient:
    """Client for communicating with KMS Lambda function"""
    
    def __init__(self, kms_lambda_function_name: str = None, kms_api_gateway_url: str = None):
        """
        Initialize KMS API Client
        
        Args:
            kms_lambda_function_name: Name of the KMS Lambda function for direct invocation
            kms_api_gateway_url: API Gateway URL for HTTP requests
        """
        self.kms_lambda_function_name = kms_lambda_function_name or os.environ.get('KMS_LAMBDA_FUNCTION_NAME', 'cspm-kms-auditor')
        self.kms_api_gateway_url = kms_api_gateway_url or os.environ.get('KMS_API_GATEWAY_URL')
        
        # Initialize Lambda client for direct invocation
        self.lambda_client = boto3.client('lambda')
        
        # Request timeout settings
        self.timeout = int(os.environ.get('KMS_API_TIMEOUT', '30'))
        
        print(f"KMS API Client initialized - Function: {self.kms_lambda_function_name}, Gateway: {self.kms_api_gateway_url}")
        
    def audit_kms_key_security(self, key_id: str, account_id: str, region: str, additional_params: Dict = None) -> Optional[Dict[str, Any]]:
        """
        Audit KMS key security (compatible with original function signature)
        
        Args:
            key_id: KMS key ID or ARN
            account_id: AWS account ID
            region: AWS region
            additional_params: Additional parameters for the audit
            
        Returns:
            Dict containing audit results or None if no findings
        """
        try:
            payload = {
                'action': 'audit_key',
                'key_id': key_id,
                'account_id': account_id,
                'region': region,
                'additional_params': additional_params or {}
            }
            
            print(f"[DEBUG] Requesting KMS audit for key: {key_id}")
            
            # Try API Gateway first, then fall back to direct Lambda invocation
            if self.kms_api_gateway_url:
                result = self._call_api_gateway('/audit-key', payload)
            else:
                result = self._invoke_lambda_directly(payload)
            
            # Extract audit results from the response
            if result and result.get('status') == 'completed':
                audit_results = result.get('audit_results')
                if audit_results:
                    print(f"[DEBUG] KMS audit completed successfully for key: {key_id}")
                    return audit_results
                else:
                    print(f"[DEBUG] KMS key is secure, no findings generated for key: {key_id}")
                    return None
            else:
                print(f"[WARNING] KMS audit failed or returned no results for key: {key_id}")
                return None
                
        except Exception as e:
            print(f"[ERROR] KMS audit failed for key {key_id}: {str(e)}")
            return None
    
    def get_kms_key_info(self, key_id: str, region: str = None) -> Dict[str, Any]:
        """
        Get basic KMS key information (lightweight call)
        
        Args:
            key_id: KMS key ID or ARN
            region: AWS region (defaults to current region)
            
        Returns:
            Dict containing key information
        """
        try:
            payload = {
                'action': 'get_key_info',
                'key_id': key_id,
                'region': region or os.environ.get('AWS_REGION', 'us-east-1')
            }
            
            print(f"[DEBUG] Requesting KMS key info for: {key_id}")
            
            # Try API Gateway first, then fall back to direct Lambda invocation
            if self.kms_api_gateway_url:
                return self._call_api_gateway('/key-info', payload)
            else:
                return self._invoke_lambda_directly(payload)
                
        except Exception as e:
            print(f"[ERROR] Get KMS key info failed for {key_id}: {str(e)}")
            return {
                'error': f"Get key info failed: {str(e)}",
                'key_id': key_id,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }
    
    def audit_multiple_keys(self, key_ids: List[str], account_id: str, region: str) -> Dict[str, Any]:
        """
        Audit multiple KMS keys
        
        Args:
            key_ids: List of KMS key IDs or ARNs
            account_id: AWS account ID
            region: AWS region
            
        Returns:
            Dict containing audit results for all keys
        """
        try:
            payload = {
                'action': 'audit_multiple_keys',
                'key_ids': key_ids,
                'account_id': account_id,
                'region': region
            }
            
            print(f"[DEBUG] Requesting KMS audit for {len(key_ids)} keys")
            
            # Try API Gateway first, then fall back to direct Lambda invocation
            if self.kms_api_gateway_url:
                return self._call_api_gateway('/audit-multiple', payload)
            else:
                return self._invoke_lambda_directly(payload)
                
        except Exception as e:
            print(f"[ERROR] Multiple KMS audit failed: {str(e)}")
            return {
                'error': f"Multiple KMS audit failed: {str(e)}",
                'key_ids': key_ids,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check if KMS Lambda service is healthy
        
        Returns:
            Dict containing health status
        """
        try:
            if self.kms_api_gateway_url:
                return self._call_api_gateway('/health', {})
            else:
                payload = {'action': 'health_check'}
                return self._invoke_lambda_directly(payload)
                
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _call_api_gateway(self, endpoint: str, payload: Dict) -> Dict[str, Any]:
        """
        Call KMS Lambda via API Gateway
        
        Args:
            endpoint: API endpoint path
            payload: Request payload
            
        Returns:
            Response from API Gateway
        """
        try:
            url = f"{self.kms_api_gateway_url.rstrip('/')}{endpoint}"
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'S3-Plugin-Client/1.0'
            }
            
            print(f"[DEBUG] Calling KMS API Gateway: {url}")
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            
            result = response.json()
            print(f"[DEBUG] KMS API Gateway response received: {response.status_code}")
            
            return result
            
        except requests.exceptions.Timeout:
            raise Exception(f"KMS API Gateway timeout after {self.timeout} seconds")
        except requests.exceptions.RequestException as e:
            raise Exception(f"KMS API Gateway request failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON response from KMS API Gateway: {str(e)}")
    
    def _invoke_lambda_directly(self, payload: Dict) -> Dict[str, Any]:
        """
        Invoke KMS Lambda function directly
        
        Args:
            payload: Request payload
            
        Returns:
            Response from Lambda function
        """
        try:
            print(f"[DEBUG] Invoking KMS Lambda directly: {self.kms_lambda_function_name}")
            
            response = self.lambda_client.invoke(
                FunctionName=self.kms_lambda_function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            
            # Parse response
            response_payload = json.loads(response['Payload'].read())
            
            # Check for Lambda execution errors
            if response.get('FunctionError'):
                raise Exception(f"KMS Lambda execution error: {response_payload}")
            
            # Check for application errors
            if response_payload.get('statusCode', 200) != 200:
                error_msg = response_payload.get('error', 'Unknown error')
                raise Exception(f"KMS Lambda application error: {error_msg}")
            
            print(f"[DEBUG] KMS Lambda direct invocation successful")
            
            # Return the result portion for direct invocations
            return response_payload.get('result', response_payload)
            
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                raise Exception(f"KMS Lambda function not found: {self.kms_lambda_function_name}")
            else:
                raise Exception(f"KMS Lambda direct invocation failed: {str(e)}")

# Global instance for backward compatibility
_kms_client = None

def get_kms_client():
    """Get or create global KMS API client instance"""
    global _kms_client
    if _kms_client is None:
        _kms_client = KMSAPIClient()
    return _kms_client

def audit_kms_key_security(key_id: str, account_id: str, region: str, kms_client=None):
    """
    Backward compatible function for existing S3 plugin code
    
    Args:
        key_id: KMS key ID or ARN
        account_id: AWS account ID
        region: AWS region
        kms_client: Ignored (for backward compatibility)
        
    Returns:
        Dict containing audit results or None if no findings
    """
    client = get_kms_client()
    return client.audit_kms_key_security(key_id, account_id, region)