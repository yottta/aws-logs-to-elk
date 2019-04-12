#!/bin/bash
set -e
sudo yum update -y  
sudo amazon-linux-extras install nginx1.12 -y  
sudo chkconfig nginx on  
sudo service nginx start

