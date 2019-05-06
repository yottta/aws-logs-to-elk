# EC2 logs forwarder to ELK

This repo contains different scripts needed to create everything is needed in order to forward EC2 logs to ELK.

## Description
This is an example on how terraform can be used in order to provision the following:
- a VPC with a public and a private subnet
- two EC2 instances, every one of them in one of the subnets
- necessary SGs that enable the communication between those 2 instances and also the communication with the rest of the world
- docker executed applications that are storing their logs directly in journald
- journald logs forwarded to CW
- a Lambda function to process the logs and forward those to an ELK stack
- a CW LogGroup trigger option for our Lambda function
- and of course a bunch of IAM policies and roles needed for making all of the above points possible

## Structure

### ansible
Three playbooks needed in three different scenarios:
* main.yml - playbook that is starting the whole provisioning process. Here the application for our Lambda function is built(a simple go application). This will be used for forwarding logs from CW to ELK. This playbook also executes the terraform scripts as well
* setup_app.yml - playbook responsible with provisioning a lightweight application
* setup_elk.yml - playbook that is responsible with provisioning the ElasticSearch and Kibana services

### terraform
* main.tf - the terraform script that contains everything needed to provision the needed AWS services in order to enable the logs forwarding
* outputs.tf - here is defined what the terraform execution should print after it's done
* secret.tfvars - file where you should update your aws_access_key and aws_secret_key

## Dependencies
This whole repo used other repos. If you encounter issues, you can check those as well:
* https://github.com/saymedia/journald-cloudwatch-logs - used to forward journald logs to CW
* https://github.com/yottta/aws-lambda-to-elk - this is the source code for Lambda function

## How do you execute this

### Prerequisites
You should have installed the following:
* docker
* python (Python3 preferably)
* ansible (2.5+)
* unzip/zip
* docker python packages

### Configure it
In `ansible/secret.tfvars` put your AWS_ACCESS_KEY and AWS_SECRET_KEY.
In `keys/` generate a SSH key, preferably not secured with a passphrase `ssh-keygen -t rsa -f aws_id_rsa`

### Provision
In `ansible/` you have to execute the following command: `ansible-playbook --connection=local --inventory localhost, main.yaml`

### Destroy
In `ansible/` you have to execute the following command: `ansible-playbook --connection=local --inventory localhost, --extra-vars "stack_state=absent" main.yaml`

### Navigate the results
After several minutes, you can get the public_dns from the public EC2 instance and putting it in a browser and accessing 5601 port (Kibana) you should see it loading. Also put in the index filtering just `logs` and save it. You should see the logs now.
