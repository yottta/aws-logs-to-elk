#!/bin/bash

sudo apt update -y
sudo apt install -y docker.io
sudo usermod -aG docker ubuntu
sudo docker run --log-driver=journald -d --rm --name=logtest -i -t alpine /bin/sh -c 'while true; do sleep 2; echo "now is $(date)"; done'
