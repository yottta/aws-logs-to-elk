provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "${var.region}"
}
data "aws_caller_identity" "current" { }

###################################################
###### KEY PAIRS ######
resource "aws_key_pair" "provisioner_key" {
  key_name   = "aws_id_rsa"
  public_key = "${file("../keys/aws_id_rsa.pub")}"
}

###################################################
####### IAM ########

# roles and policies needed to allow to the app stored on ec2 to write logs to cw
resource "aws_iam_policy" "cloud_watch_logs_policy" {
  name        = "cloud_watch_logs_policy"
  path        = "/"
  description = "Policy needed to send logs to cloud watch"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "arn:aws:logs:*:*:log-group:*",
                "arn:aws:logs:*:*:log-group:*:log-stream:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role" "allow_ec2_write_logs_to_cw" {
  name = "allow_ec2_write_logs_to_cw"

  description = "Role that is used for EC2 instances in order to allow acces to CW logs"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "cloud_watch_logs_policy_attachment_to_ec2_role" {
  role       = "${aws_iam_role.allow_ec2_write_logs_to_cw.name}"
  policy_arn = "${aws_iam_policy.cloud_watch_logs_policy.arn}"
}

resource "aws_iam_instance_profile" "cw_iam_instance_profile" {
  name = "cw_iam_instance_profile"
  role = "${aws_iam_role.allow_ec2_write_logs_to_cw.name}"
}

# lambda needed roles and policies
resource "aws_iam_policy" "lambda_forward_cw_to_elk_policy" {
  name        = "lambda_forward_cw_to_elk_policy"
  path        = "/"
  description = "Policy needed for lambda to be able to write its own logs to CW"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.lambda_cw_to_elk_logs.name}:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role" "lambda_forward_cw_to_elk_role" {
  name = "lambda_forward_cw_to_elk_role"

  description = "Role that is used for by lambda to be able to write its own logs to CW"
  path        = "/service-role/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_forward_cw_to_elk_policy_attach_to_role" {
  role       = "${aws_iam_role.lambda_forward_cw_to_elk_role.name}"
  policy_arn = "${aws_iam_policy.lambda_forward_cw_to_elk_policy.arn}"
}

####################################################
######## CLOUD WATCH LOGS ########
resource "aws_cloudwatch_log_group" "app_journald_logs" {
  name              = "app_journald_logs"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "lambda_cw_to_elk_logs" {
  name              = "/aws/lambda/${aws_lambda_function.forward_cw_to_elk.function_name}"
  retention_in_days = 14
}


####################################################
######## NETWORKING ########
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "test_vpc"

  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a"]
  private_subnets = ["10.0.1.0/24"]
  public_subnets  = ["10.0.101.0/24"]

  enable_dns_support = true
  enable_dns_hostnames = true

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = {
    Owner       = "user"
    Environment = "dev"
  }

  vpc_tags = {
    Name = "test_vpc_name"
  }
}

resource "aws_security_group" "public_sg" {
  name        = "public_sg"
  description = "Allow access to the public resources"
  vpc_id      = "${module.vpc.vpc_id}"
}

resource "aws_security_group_rule" "allow_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "${aws_security_group.public_sg.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_kibana_access" {
  type              = "ingress"
  from_port         = 5601
  to_port           = 5601
  protocol          = "tcp"
  security_group_id = "${aws_security_group.public_sg.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_es_access" {
  type              = "ingress"
  from_port         = 9200
  to_port           = 9200
  protocol          = "tcp"
  security_group_id = "${aws_security_group.public_sg.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  security_group_id = "${aws_security_group.public_sg.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = "${aws_security_group.public_sg.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_ssh_to_private_sg" {
  type                     = "egress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.public_sg.id}"
  source_security_group_id = "${aws_security_group.private_sg.id}"
}

resource "aws_security_group" "private_sg" {
  name        = "private_sg"
  description = "Allow ssh ingress trafic just from the public_sg"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    security_groups = [ "${aws_security_group.public_sg.id}" ]
  }
}

###################################################
####### INSTANCES ########
resource "aws_instance" "elk_instance" {
  ami                    = "${lookup(var.amis, var.region)}"
  instance_type          = "${var.small_instance_type}"
  key_name 	         = "${aws_key_pair.provisioner_key.key_name}"
  vpc_security_group_ids = [ "${aws_security_group.public_sg.id}", "${module.vpc.default_security_group_id}" ]
  subnet_id              = "${module.vpc.public_subnets[0]}"
}

resource "aws_instance" "app_instance" {
  ami           = "${lookup(var.amis, var.region)}"
  instance_type = "${var.default_instance_type}"
  key_name 	= "${aws_key_pair.provisioner_key.key_name}"
  vpc_security_group_ids = [ "${aws_security_group.private_sg.id}", "${module.vpc.default_security_group_id}" ]
  iam_instance_profile = "${aws_iam_instance_profile.cw_iam_instance_profile.name}"

  subnet_id   = "${module.vpc.private_subnets[0]}"
}

resource "aws_eip" "elk_public_ip" {
  instance = "${aws_instance.elk_instance.id}"
}

####################################################
####### LAMBDA ######
resource "aws_lambda_function" "forward_cw_to_elk" {
  filename         = "${var.lambda_app_zip_file_path}"
  function_name    = "forward_cw_to_elk"
  role             = "${aws_iam_role.lambda_forward_cw_to_elk_role.arn}"
  handler          = "forwarder"
  source_code_hash = "${filebase64sha256(var.lambda_app_zip_file_path)}"
  runtime          = "go1.x"
  
  environment {
    variables = {
      ES_HOST  = "http://${aws_eip.elk_public_ip.public_dns}"
      ES_PORT  = 9200
      ES_INDEX = "logs"
    }
  }
}

resource "aws_lambda_permission" "allow_cw_to_call_forward_to_elk_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.forward_cw_to_elk.function_name}"
  principal     = "logs.${var.region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.app_journald_logs.arn}"
}

resource "aws_cloudwatch_log_subscription_filter" "subscription_app_logs_to_lambda" {
  name            = "subscription_app_logs_to_lambda"
  filter_pattern  = ""
  log_group_name  = "app_journald_logs"
  destination_arn = "${aws_lambda_function.forward_cw_to_elk.arn}"
}

####################################################
####### PROVISONING ######
resource "null_resource" "copy_ssh_key" {
  triggers {
    elk_instanceId = "${aws_instance.elk_instance.id}"
    app_instanceId = "${aws_instance.app_instance.id}"
  }
  depends_on = [
    "aws_instance.elk_instance"
  ]

  connection {
    type              = "ssh"
    user              = "ubuntu"
    host	      = "${aws_eip.elk_public_ip.public_ip}"
    private_key       = "${file("../keys/aws_id_rsa")}"
  }

  provisioner "file" {
    source = "../keys/aws_id_rsa"
    destination = "/home/ubuntu/aws_id_rsa"
  }
}

resource "null_resource" "copy_ansible_playbooks" {
  triggers {
    elk_instanceId = "${aws_instance.elk_instance.id}"
    app_instanceId = "${aws_instance.app_instance.id}"
  }
  depends_on = [
    "aws_instance.elk_instance"
  ]

  connection {
    type              = "ssh"
    user              = "ubuntu"
    host	      = "${aws_eip.elk_public_ip.public_ip}"
    private_key       = "${file("../keys/aws_id_rsa")}"
  }

  provisioner "file" {
    source = "../ansible"
    destination = "/home/ubuntu/"
  }
}

resource "null_resource" "provisioning_instances" {
  triggers {
    elk_instanceId = "${aws_instance.elk_instance.id}"
    app_instanceId = "${aws_instance.app_instance.id}"
  }
  depends_on = [
    "null_resource.copy_ssh_key",
    "null_resource.copy_ansible_playbooks",
    "aws_instance.elk_instance",
    "aws_instance.app_instance"
  ]

  connection {
    type              = "ssh"
    user              = "ubuntu"
    host	      = "${aws_eip.elk_public_ip.public_ip}"
    private_key       = "${file("../keys/aws_id_rsa")}"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 600 /home/ubuntu/aws_id_rsa",
      "sudo apt-add-repository -y ppa:ansible/ansible && sudo apt update -y && sudo apt install -y ansible",
      "ansible-playbook --connection=local --become --inventory localhost, /home/ubuntu/ansible/setup_ek.yaml",
      "ansible-playbook --extra-vars \"my_host=${aws_instance.app_instance.private_ip} cloud_watch_log_group=${aws_cloudwatch_log_group.app_journald_logs.name}\" --ssh-common-args='-o StrictHostKeyChecking=no' --inventory localhost, /home/ubuntu/ansible/setup_app.yaml"
    ]
  }
}
