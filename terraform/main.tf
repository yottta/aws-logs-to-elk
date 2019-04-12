provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "${var.region}"
}

###################################################
###### KEY PAIRS ######
resource "aws_key_pair" "provisioner_key" {
  key_name   = "aws_id_rsa"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJ0HDUFW7bc7tyAhTmm9n1dxOQD2B4ANHQIqIgxVh9YBjTUERn99jF6vxrw8yKFDe4rGF3Ghp1ATRbL8Fx6dTNGZ3jfNXMaygxp1/F+3Kmp2lyKYPvKvd1A+XI4pPRVH2zJGpnY0wgTcJocgMlNwI8UNm5ZX/f/SzDbYvfgSW0QrDqpiBM1LyEr06OCBpRAQyntkupuRgJZ4PtQF/aFYD8q1bCoNfEaylFJIkh1FSM6QOKTMOM+LiGGAvHUrwn+x2soZbGoxgWF0RGog/rPL55P5mk5l8tO6JqL3pxORhrtHJZ4Dsq3hcavqaHk8gLH7KZB8Q64IpIOAkJGDxnyneB andrei.ciobanu@bv030635mc"
}

## need IAM role for journald script, needs to download the journald crawler and add the conf file 
## config file |
##log_group = "app_journald"
##state_file = "/home/ubuntu/journald-cloudwatch-logs/state"
## create log group in cloudwatch (DONE)

###################################################
####### IAM ########
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

####################################################
######## CLOUD WATCH LOGS ########
resource "aws_cloudwatch_log_group" "app_journald_logs" {
  name = "app_journald_logs"
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
  instance_type          = "${var.default_instance_type}"
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
####### PROVISONING ######
resource "null_resource" "copy_ssh_key" {
  triggers {
    public_ip = "${aws_instance.elk_instance.public_ip}"
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
    public_ip = "${aws_instance.elk_instance.public_ip}"
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
    public_ip = "${aws_instance.elk_instance.public_ip}"
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
#      "ansible-playbook --connection=local --become --inventory localhost, /home/ubuntu/ansible/setup_ek.yaml",
      "ansible-playbook --extra-vars \"my_host=${aws_instance.app_instance.private_ip}\" --inventory localhost, /home/ubuntu/ansible/setup_app.yaml"
#      "sudo apt update -y && sudo apt install -y docker.io && sudo sysctl -w vm.max_map_count=262144 && sudo usermod -aG docker ubuntu && sudo docker run -d --name elkstack -e ES_JAVA_OPTS=\"-Xms352m -Xmx352m\" --memory=\"512m\" -p 80:80 -p 443:443 -p 9200:9200 blacktop/elastic-stack"
    ]
  }
  provisioner "remote-exec" {
    inline = [
      "sudo apt update -y",
      "sudo apt install nginx",
    ]
  }
}

#resource "null_resource" "copy_provisioning_app_instance_script" {
#  triggers {
#    public_ip = "${aws_instance.elk_instance.public_ip}"
#    private_ip = "${aws_instance.app_instance.private_ip}"
#  }
#
#  connection {
#    type              = "ssh"
#    user              = "ubuntu"
#    host	      = "${aws_eip.elk_public_ip.public_ip}"
#    private_key       = "${file("../keys/aws_id_rsa")}"
#  }
#
#  provisioner "file" {
#    source = "provision_app_instance.sh"
#    destination = "/home/ubuntu/provision_app_instance.sh"
#  }
#}
#

#resource "null_resource" "provision_app_instance" {
#  triggers {
#    public_ip  = "${aws_instance.elk_instance.public_ip}"
#    private_ip = "${aws_instance.app_instance.private_ip}"
#  }
#
#  connection {
#    type              = "ssh"
#    user              = "ubuntu"
#    host	      = "${aws_eip.elk_public_ip.public_ip}"
#    private_key       = "${file("../keys/aws_id_rsa")}"
#  }
#
#  depends_on = [
#    "null_resource.copy_ssh_key",
#    "null_resource.copy_provisioning_app_instance_script",
#    "aws_instance.app_instance"
#  ]
#
#  provisioner "remote-exec" {
#    inline = [
#        "chmod 600 aws_id_rsa && ssh -o \"StrictHostKeyChecking no\" -i /home/ubuntu/aws_id_rsa ubuntu@${aws_instance.app_instance.private_ip} 'bash -s' < provision_app_instance.sh"
#    ]
#  }
#}
#


# ansible-playbook --connection=local --inventory 127.0.0.1, main.yml
