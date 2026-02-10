from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import random

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB connection
MONGO_URI = os.getenv('MONGO_URI')
DATABASE_NAME = os.getenv('DATABASE_NAME', 'csmp_findings')
COLLECTION_NAME = os.getenv('COLLECTION_NAME', 's3_audit_findings')

try:
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    print(f"Connected to MongoDB: {DATABASE_NAME}")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    client = None
    db = None
    collection = None

# Custom JSON serialization for MongoDB ObjectId and datetime
def custom_json_serializer(obj):
    """Custom JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

app.json.default = custom_json_serializer

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    mongo_status = "connected" if client else "disconnected"
    return jsonify({
        "status": "healthy",
        "mongodb": mongo_status,
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/findings', methods=['GET'])
def get_findings():
    """Get all security findings with optional filtering"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        severity = request.args.get('severity')
        service = request.args.get('service')
        status = request.args.get('status')
        search = request.args.get('search')
        
        # Build filter query
        filter_query = {}
        
        if severity:
            filter_query['severity'] = severity
        if service:
            filter_query['service'] = service
        if status:
            filter_query['status'] = status
        if search:
            filter_query['$or'] = [
                {'title': {'$regex': search, '$options': 'i'}},
                {'description': {'$regex': search, '$options': 'i'}},
                {'resource_id': {'$regex': search, '$options': 'i'}}
            ]
        
        # Calculate skip value for pagination
        skip = (page - 1) * limit
        
        # Get total count
        total_count = collection.count_documents(filter_query)
        
        # Get findings with pagination
        findings = list(collection.find(filter_query)
                       .sort('timestamp', -1)
                       .skip(skip)
                       .limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for finding in findings:
            finding['_id'] = str(finding['_id'])
            if 'timestamp' in finding and isinstance(finding['timestamp'], datetime):
                finding['timestamp'] = finding['timestamp'].isoformat()
        
        return jsonify({
            "findings": findings,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "pages": (total_count + limit - 1) // limit
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/findings/<finding_id>', methods=['GET'])
def get_finding_by_id(finding_id):
    """Get a specific finding by ID"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        finding = collection.find_one({"_id": ObjectId(finding_id)})
        if not finding:
            return jsonify({"error": "Finding not found"}), 404
        
        finding['_id'] = str(finding['_id'])
        if 'timestamp' in finding and isinstance(finding['timestamp'], datetime):
            finding['timestamp'] = finding['timestamp'].isoformat()
        
        return jsonify(finding)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/findings/<finding_id>/status', methods=['PUT'])
def update_finding_status(finding_id):
    """Update the status of a finding"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({"error": "Status is required"}), 400
        
        result = collection.update_one(
            {"_id": ObjectId(finding_id)},
            {
                "$set": {
                    "status": new_status,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({"error": "Finding not found"}), 404
        
        return jsonify({"message": "Status updated successfully"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        # Get total findings count
        total_findings = collection.count_documents({})
        
        # Get findings by severity
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        severity_stats = list(collection.aggregate(severity_pipeline))
        
        # Get findings by service
        service_pipeline = [
            {"$group": {"_id": "$service", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        service_stats = list(collection.aggregate(service_pipeline))
        
        # Get findings by status
        status_pipeline = [
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        status_stats = list(collection.aggregate(status_pipeline))
        
        # Get recent findings (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_findings = collection.count_documents({
            "timestamp": {"$gte": seven_days_ago}
        })
        
        return jsonify({
            "total_findings": total_findings,
            "recent_findings": recent_findings,
            "severity_distribution": severity_stats,
            "service_distribution": service_stats,
            "status_distribution": status_stats
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/findings/timeline', methods=['GET'])
def get_findings_timeline():
    """Get findings timeline data for charts"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=days)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_date}}},
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$timestamp"},
                        "month": {"$month": "$timestamp"},
                        "day": {"$dayOfMonth": "$timestamp"}
                    },
                    "count": {"$sum": 1},
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}
                    },
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}
                    }
                }
            },
            {"$sort": {"_id": 1}}
        ]
        
        timeline_data = list(collection.aggregate(pipeline))
        
        # Format the data for frontend consumption
        formatted_data = []
        for item in timeline_data:
            date_obj = datetime(
                item['_id']['year'],
                item['_id']['month'],
                item['_id']['day']
            )
            formatted_data.append({
                "date": date_obj.strftime("%Y-%m-%d"),
                "total": item['count'],
                "critical": item['critical'],
                "high": item['high'],
                "medium": item['medium'],
                "low": item['low']
            })
        
        return jsonify(formatted_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/populate-sample-data', methods=['POST'])
def populate_sample_data():
    """Populate database with sample AWS security findings"""
    if collection is None:
        return jsonify({"error": "Database not connected"}), 500
    
    try:
        
        # Sample data generation
        aws_accounts = ['123456789012', '987654321098', '456789123456']
        regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
        bucket_names = [
            'company-data-backup', 'user-uploads-prod', 'analytics-logs',
            'static-website-assets', 'database-backups', 'application-logs',
            'media-files-storage', 'config-files-bucket', 'temp-processing-data'
        ]
        
        findings = []
        
        # Generate S3 ACL enabled findings
        for i in range(5):
            bucket_name = random.choice(bucket_names) + f"-{random.randint(100, 999)}"
            account_id = random.choice(aws_accounts)
            region = random.choice(regions)
            
            finding = {
                "finding_id": f"s3-acl-{random.randint(10000, 99999)}",
                "title": "S3 Bucket ACLs Enabled",
                "description": f"S3 bucket '{bucket_name}' has Access Control Lists (ACLs) enabled, which may allow unintended access permissions.",
                "severity": random.choice(["Medium", "High"]),
                "service": "S3",
                "resource_id": f"arn:aws:s3:::{bucket_name}",
                "resource_name": bucket_name,
                "account_id": account_id,
                "region": region,
                "status": random.choice(["Open", "In Progress", "Resolved"]),
                "compliance_standards": ["AWS Config", "CIS AWS Foundations"],
                "remediation": {
                    "description": "Disable S3 bucket ACLs and use bucket policies for access control",
                    "steps": [
                        "Navigate to S3 console",
                        f"Select bucket '{bucket_name}'",
                        "Go to Permissions tab",
                        "Edit Object Ownership settings",
                        "Select 'Bucket owner enforced' to disable ACLs",
                        "Review and update bucket policies as needed"
                    ],
                    "aws_cli_command": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
                },
                "risk_score": random.randint(60, 85),
                "first_detected": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
                "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(1, 24))).isoformat(),
                "tags": {
                    "Environment": random.choice(["Production", "Staging", "Development"]),
                    "Team": random.choice(["DevOps", "Security", "Data"]),
                    "CostCenter": f"CC-{random.randint(1000, 9999)}"
                },
                "metadata": {
                    "scan_type": "Configuration Assessment",
                    "scanner": "AWS Config",
                    "rule_name": "s3-bucket-acl-prohibited",
                    "finding_type": "Security"
                }
            }
            findings.append(finding)
        
        # Generate S3 public access enabled findings
        for i in range(6):
            bucket_name = random.choice(bucket_names) + f"-{random.randint(100, 999)}"
            account_id = random.choice(aws_accounts)
            region = random.choice(regions)
            
            public_access_types = [
                "Block Public ACLs: False",
                "Ignore Public ACLs: False", 
                "Block Public Policy: False",
                "Restrict Public Buckets: False"
            ]
            
            finding = {
                "finding_id": f"s3-public-{random.randint(10000, 99999)}",
                "title": "S3 Bucket Public Access Enabled",
                "description": f"S3 bucket '{bucket_name}' has public access settings enabled, potentially exposing data to unauthorized users.",
                "severity": random.choice(["High", "Critical"]),
                "service": "S3",
                "resource_id": f"arn:aws:s3:::{bucket_name}",
                "resource_name": bucket_name,
                "account_id": account_id,
                "region": region,
                "status": random.choice(["Open", "In Progress"]),
                "compliance_standards": ["AWS Config", "CIS AWS Foundations", "PCI DSS"],
                "remediation": {
                    "description": "Block all public access to the S3 bucket",
                    "steps": [
                        "Navigate to S3 console",
                        f"Select bucket '{bucket_name}'",
                        "Go to Permissions tab",
                        "Click 'Edit' on Block public access settings",
                        "Check all four options to block public access",
                        "Save changes and confirm"
                    ],
                    "aws_cli_command": f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                },
                "risk_score": random.randint(80, 95),
                "first_detected": (datetime.utcnow() - timedelta(days=random.randint(1, 45))).isoformat(),
                "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(1, 12))).isoformat(),
                "details": {
                    "public_access_settings": random.choice(public_access_types),
                    "bucket_policy": "Present" if random.choice([True, False]) else "None",
                    "website_hosting": "Enabled" if random.choice([True, False]) else "Disabled"
                },
                "tags": {
                    "Environment": random.choice(["Production", "Staging", "Development"]),
                    "Team": random.choice(["DevOps", "Security", "Data", "Frontend"]),
                    "CostCenter": f"CC-{random.randint(1000, 9999)}",
                    "Criticality": "High"
                },
                "metadata": {
                    "scan_type": "Configuration Assessment",
                    "scanner": "AWS Config",
                    "rule_name": "s3-bucket-public-access-prohibited",
                    "finding_type": "Security"
                }
            }
            findings.append(finding)
        
        # Add additional findings
        additional_findings = [
            {
                "finding_id": f"s3-encryption-{random.randint(10000, 99999)}",
                "title": "S3 Bucket Encryption Not Enabled",
                "description": f"S3 bucket 'logs-bucket-{random.randint(100, 999)}' does not have server-side encryption enabled.",
                "severity": "Medium",
                "service": "S3",
                "resource_id": f"arn:aws:s3:::logs-bucket-{random.randint(100, 999)}",
                "resource_name": f"logs-bucket-{random.randint(100, 999)}",
                "account_id": random.choice(aws_accounts),
                "region": random.choice(regions),
                "status": "Open",
                "compliance_standards": ["AWS Config", "SOC 2"],
                "risk_score": random.randint(50, 70),
                "first_detected": (datetime.utcnow() - timedelta(days=random.randint(5, 20))).isoformat(),
                "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(6, 48))).isoformat(),
                "tags": {
                    "Environment": "Production",
                    "Team": "Security",
                    "CostCenter": f"CC-{random.randint(1000, 9999)}"
                },
                "metadata": {
                    "scan_type": "Configuration Assessment",
                    "scanner": "AWS Config",
                    "rule_name": "s3-bucket-server-side-encryption-enabled",
                    "finding_type": "Security"
                }
            },
            {
                "finding_id": f"s3-versioning-{random.randint(10000, 99999)}",
                "title": "S3 Bucket Versioning Not Enabled",
                "description": f"S3 bucket 'backup-storage-{random.randint(100, 999)}' does not have versioning enabled.",
                "severity": "Low",
                "service": "S3",
                "resource_id": f"arn:aws:s3:::backup-storage-{random.randint(100, 999)}",
                "resource_name": f"backup-storage-{random.randint(100, 999)}",
                "account_id": random.choice(aws_accounts),
                "region": random.choice(regions),
                "status": "Resolved",
                "compliance_standards": ["AWS Config"],
                "risk_score": random.randint(30, 50),
                "first_detected": (datetime.utcnow() - timedelta(days=random.randint(10, 60))).isoformat(),
                "last_updated": (datetime.utcnow() - timedelta(days=random.randint(1, 5))).isoformat(),
                "tags": {
                    "Environment": "Production",
                    "Team": "Data",
                    "CostCenter": f"CC-{random.randint(1000, 9999)}"
                },
                "metadata": {
                    "scan_type": "Configuration Assessment",
                    "scanner": "AWS Config",
                    "rule_name": "s3-bucket-versioning-enabled",
                    "finding_type": "Security"
                }
            }
        ]
        
        findings.extend(additional_findings)
        
        # --- Generate KMS Findings ---
        for i in range(5):
            findings.append({
                "finding_id": f"kms-rot-{random.randint(10000, 99999)}",
                "title": "KMS Key Rotation Not Enabled",
                "description": "Automatic key rotation is not enabled for a customer managed key.",
                "severity": random.choice(["Medium", "High"]),
                "service": "KMS",
                "resource_id": f"arn:aws:kms:us-east-1:123456789012:key/{random.randint(100000, 999999)}",
                "resource_name": f"app-data-key-{random.randint(1, 10)}",
                "account_id": random.choice(aws_accounts),
                "region": random.choice(regions),
                "status": random.choice(["Open", "In Progress", "Resolved"]),
                "compliance_standards": ["CIS AWS Foundations"],
                "risk_score": random.randint(50, 70),
                "first_detected": (datetime.utcnow() - timedelta(days=random.randint(5, 30))).isoformat(),
                "last_updated": datetime.utcnow().isoformat(),
                "metadata": {"scan_type": "Key Management Audit", "scanner": "AWS Config"}
            })
        
        # Clear existing data and insert new findings
        collection.delete_many({})
        result = collection.insert_many(findings)
        
        # Get summary statistics
        total_count = len(result.inserted_ids)
        severity_counts = {}
        service_counts = {}
        status_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            service = finding.get('service', 'Unknown')
            status = finding.get('status', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            service_counts[service] = service_counts.get(service, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return jsonify({
            "success": True,
            "message": f"Successfully populated {total_count} sample findings",
            "summary": {
                "total_findings": total_count,
                "by_severity": severity_counts,
                "by_service": service_counts,
                "by_status": status_counts
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- SIMULATION ENDPOINTS ---
from simulation_service import simulation_service

@app.route('/api/simulate/s3', methods=['POST'])
def simulate_s3_vulnerability():
    """Trigger creation of a vulnerable S3 bucket"""
    try:
        result = simulation_service.create_vulnerable_s3_bucket()
        if result.get("success"):
            return jsonify(result), 201
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/simulate/cleanup', methods=['POST'])
def cleanup_simulated_resource():
    """Cleanup a specific simulated resource"""
    try:
        data = request.get_json()
        resource_id = data.get('resource_id')
        if not resource_id:
            return jsonify({"error": "resource_id is required"}), 400
            
        result = simulation_service.cleanup_resource(resource_id)
        if result.get("success"):
            return jsonify(result), 200
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
