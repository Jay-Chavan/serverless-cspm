# MongoDB Configuration Variables
variable "mongodb_uri" {
  description = "MongoDB Atlas connection string"
  type        = string
  default     = ""
  sensitive   = true
}

variable "mongodb_database" {
  description = "MongoDB database name"
  type        = string
  default     = "cspm_findings"
}

variable "mongodb_collection_kms" {
  description = "MongoDB collection name for KMS findings"
  type        = string
  default     = "kms_security_findings"
}

variable "mongodb_collection_s3" {
  description = "MongoDB collection name for S3 findings"
  type        = string
  default     = "s3_security_findings"
}