# OpenSASE PoP Deployment - Production Environment

pop_name        = "pop-nyc"
cloud_provider  = "aws"
region          = "us-east-1"
environment     = "production"

# High Availability
enable_ha      = true
instance_count = 2
instance_type  = "c6i.2xlarge"

# Domain
domain = "opensase.io"

# Tags
tags = {
  Team        = "Platform"
  CostCenter  = "Infrastructure"
  Compliance  = "SOC2"
}
