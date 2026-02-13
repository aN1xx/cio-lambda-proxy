terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "cio-lambda.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "terraform-remote-state"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

data "terraform_remote_state" "infra" {
  backend = "s3"

  config = {
    bucket = "your-terraform-state-bucket"
    key    = "env:/${terraform.workspace}/infra.tfstate"
    region = "eu-central-1"
  }
}

data "terraform_remote_state" "api-gw-lambda" {
  backend = "s3"

  config = {
    bucket = "your-terraform-state-bucket"
    key    = "env:/${terraform.workspace}/api-gateway.tfstate"
    region = "eu-central-1"
  }
}
