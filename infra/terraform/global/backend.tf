# OpenSASE Global Terraform Backend
# Remote state configuration

terraform {
  backend "s3" {
    bucket         = "opensase-terraform-state"
    key            = "global/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "opensase-terraform-locks"
    
    # Enable state locking
    skip_metadata_api_check = false
  }
}

# Alternative backends for different cloud providers

# GCS Backend (for GCP-primary deployments)
# terraform {
#   backend "gcs" {
#     bucket  = "opensase-terraform-state"
#     prefix  = "global"
#   }
# }

# Azure Backend
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "opensase-terraform-rg"
#     storage_account_name = "opensaseterraform"
#     container_name       = "tfstate"
#     key                  = "global/terraform.tfstate"
#   }
# }

# State Locking DynamoDB Table (created separately)
# resource "aws_dynamodb_table" "terraform_locks" {
#   name         = "opensase-terraform-locks"
#   billing_mode = "PAY_PER_REQUEST"
#   hash_key     = "LockID"
#
#   attribute {
#     name = "LockID"
#     type = "S"
#   }
# }
