variable "opa_conf_bucket_name" {
    type = string
  
}

variable "allowed_ports_opa_server" {
    type = set(string)
    default = [ "8181" ]
}

variable "iam_instance_profile" {
  
}