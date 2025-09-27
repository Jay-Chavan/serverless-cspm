# Use this file if you want to store your custom lambda and policy config files, you can download them from our bucket , modify them
# and store them in your bucket using the below code
# place your lambda_functions_zip into lambda_functions folder
# place your policy as code config files under config_files_folder
# Make sure the terraform block under lambda follows your bucket structure





resource "aws_s3_bucket" "serverless_cspm_files" {
    bucket = "jayserverlesscspmfilesbucket"
    tags = {
      "Type" = "Policy as code bucket",
      "Confidentiality" = "High"
    }
  
}

locals {
  config_files = fileset("${path.module}/config_files", "**")
  lambda_functions = fileset("${path.module}/lambda_functions","**")
}

resource "aws_s3_object" "config_files" {
  for_each = { for file in local.config_files : file => file }

  bucket = aws_s3_bucket.serverless_cspm_files.id
  key    = "config_files/${each.key}"  # Keep directory structure
  source = "${path.module}/config_files/${each.key}"
  etag   = filemd5("${path.module}/config_files/${each.key}")
}

resource "aws_s3_object" "lambda_functions" {
  for_each = { for file in local.lambda_functions : file => file }

  bucket = aws_s3_bucket.serverless_cspm_files.id
  key    = "lambda_functions/${each.key}"  # Keep directory structure
  source = "${path.module}/lambda_functions/${each.key}"
  etag   = filemd5("${path.module}/lambda_functions/${each.key}")
}
  

