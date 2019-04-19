variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "lambda_app_zip_file_path" {}

variable "default_instance_type" {
  default = "t2.micro"
}

variable "small_instance_type" {
    default = "t2.small"
}

variable "amis" {
  type = "map"
  default = {
    "eu-west-1" = "ami-08660f1c6fb6b01e7"
  }
}

variable "region" {
  default = "eu-west-1"
}

