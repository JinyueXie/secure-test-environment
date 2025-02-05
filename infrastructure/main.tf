// main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

// VPC for isolation
resource "aws_vpc" "test_env_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "secure-test-environment"
  }
}

// Security Group with strict rules
resource "aws_security_group" "test_env_sg" {
  name        = "test-env-security-group"
  description = "Security group for test environment"
  vpc_id      = aws_vpc.test_env_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  // Replace with your IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

// EC2 instance with encrypted volumes
resource "aws_instance" "test_env" {
  ami           = "ami-0c55b159cbfafe1f0"  // Ubuntu AMI
  instance_type = "t2.micro"

  root_block_device {
    encrypted = true
  }

  vpc_security_group_ids = [aws_security_group.test_env_sg.id]

  tags = {
    Name = "secure-test-environment"
  }
}

// S3 bucket for test data with encryption
resource "aws_s3_bucket" "test_data" {
  bucket = "secure-test-data-${random_string.bucket_suffix.result}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_data" {
  bucket = aws_s3_bucket.test_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

// IAM role with least privilege
resource "aws_iam_role" "test_env_role" {
  name = "test-env-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

// Minimal IAM policy
resource "aws_iam_role_policy" "test_env_policy" {
  name = "test-env-policy"
  role = aws_iam_role.test_env_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.test_data.arn}/*"
        ]
      }
    ]
  })
}
