resource "aws_lambda_function" "s3findings_lambda_function" {
    for_each = var.s3_key_lambda_functions
    function_name = each.key
    role = "arn:aws:iam::${var.account_id}:role/${each.key}"
    handler = var.lambda_handler
    runtime = var.runtime
    environment {
      variables = {
      opa_server_ip = var.ec2_public_ip 
      
    }

    }
    s3_bucket = var.s3_bucket_name
    s3_key = "lambda_functions/${each.value}"
    
    
}



