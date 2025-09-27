variable "rolenames" {
    type = string
    default = "opa_server_role_ec2" 
  
}

variable "lambda_role_with_their_policies" {
    type = map(string)
    default = {
      "s3finding_lambda_function" = "s3_properties_list_permissions",
      "rds_lambda_function" = "rds_properties_list_permissions"
    }
}

variable "account_id" {
    type = string
    default = "554739427981"

}
