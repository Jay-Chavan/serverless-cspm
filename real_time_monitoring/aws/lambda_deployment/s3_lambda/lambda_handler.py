"""
Lambda Handler Entry Point for S3 CSPM Auditor
This file serves as the main entry point for the AWS Lambda function
"""

# Import the actual handler from S3_findings module
from S3_findings import lambda_handler

# Re-export the handler function so AWS Lambda can find it
__all__ = ['lambda_handler']

# The lambda_handler function is now available at the module level
# AWS Lambda will call: lambda_handler.lambda_handler(event, context)