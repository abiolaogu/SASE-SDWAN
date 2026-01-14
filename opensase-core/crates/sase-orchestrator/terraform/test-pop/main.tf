
# OpenSASE PoP: test-pop
# Region: us-east-1 (US East)

module "vpc" {
  source = "./modules/vpc"
  
  vpc_cidr = "10.0.0.0/16"
  pop_id   = "test-pop"
}

module "security_groups" {
  source = "./modules/security"
  vpc_id = module.vpc.vpc_id
}

resource "aws_instance" "pop" {
  count         = 1
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.small"
  
  subnet_id              = module.vpc.public_subnet_ids[count.index % length(module.vpc.public_subnet_ids)]
  vpc_security_group_ids = [module.security_groups.pop_sg_id]
  
  user_data = templatefile("${path.module}/userdata.sh", {
    pop_id = "test-pop"
  })
  
  tags = {
    Name    = "test-pop-${count.index}"
    Project = "opensase"
  }
}


data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}
