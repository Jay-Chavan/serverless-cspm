module "s3_module" {
    source = "./modules/s3"

  
}

module "iam_module" {
    source = "./modules/iam"

  
}

module "ec2_module_opa_server" {
    depends_on = [ module.s3_module , module.iam_module]
    source = "./modules/ec2-opa"
    opa_conf_bucket_name = module.s3_module.bucket_name

    iam_instance_profile = module.iam_module.instance_profile
  
}

module "lambda_module" {
    depends_on = [ module.s3_module , module.iam_module ]
    source = "./modules/lambda"
    s3_bucket_name = module.s3_module.bucket_name
    ec2_public_ip = module.ec2_module_opa_server.public_ip
    
  
}

module "eventbridge_module" {
    depends_on = [ module.s3_module , module.iam_module ]
    source = "./modules/eventbridge"
    environment = "dev"
    
    tags = {
        Environment = "dev"
        Project = "CSPM"
        Component = "EventBridge"
    }
}

module "lambda_auditors_module" {
    depends_on = [ module.s3_module , module.iam_module, module.ec2_module_opa_server, module.eventbridge_module ]
    source = "./modules/lambda-auditors"
    opa_server_ip = module.ec2_module_opa_server.public_ip
    account_id = "554739427981"  # Update with your actual account ID
    environment = "dev" 
    
    # MongoDB Configuration
    mongodb_uri = var.mongodb_uri
    mongodb_database = var.mongodb_database
    mongodb_collection_kms = var.mongodb_collection_kms
    mongodb_collection_s3 = var.mongodb_collection_s3
    
    # SQS Queue ARN from EventBridge module
    sqs_queue_arn = module.eventbridge_module.sqs_queue_arn
}


