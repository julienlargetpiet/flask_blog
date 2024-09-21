#!bin/bash

sed s/username/$(whoami)/g -i flask_blog.service
sed s/server_ip/$(curl ipinfo.io/ip)/g -i flask_blog.service
sudo cp /etc/systemd/system/flask_blog.service


