# flask_blog

A personnal blog website built with the Flask Framework.

Example: https://julienlargetpiet.xyz

## WebPages Architecture

### Home webpage

Is the first webpage a user will encounter entering your websites.
It shows:

If you are only a user:

- A recommendation button that can be pressed once and only **connected to an account**
- a link to the **blog post feed**
- a link to the **news feed**
- a link to your **recommendations**
- a link to **create an account (username and strong password required)**
- a link to change password
- a link to **SignIn**
- a link to **SignOut**

More if you are the administrator:

- a **customisable description** of your blog with a picture, this can be edited by clicking on the administration pannel at thebottom of the page.
- a link to the webpage where you will upload your blog posts
- a link to the webpage where you will upload your news
- a link to the webpage where you will edit your recommended websites
- an administration pannel

### Blog Post Feed

It is a webpage where your blog posts are sorted descendly by the publication date.
A search bar is present that let the users to search for specific posts via search tags that you have included in your posts when uloading it.
You can also disable comments for all posts via this webpage.

### News Feed

Same as the post feed but for your news.

### Blog Post

It is a webpage where a post is, comments are allowed but you can turn it off. (Responses to comments are possible)
Posts are editable and it will be notifiable by anyone. Posts support html / markdown / local files links (see following)

### News post

It is a webpage where a news post is, comments are not possible on the news post, but you can edit a news (which will be notifiable by anyone). News support html / markdown / local files links (see following)

### Add Post

It is a webpage where you can write your news post in **html and/or markown, you can add files with the path `../../static/files/filename`**

### Add News 

It is the same as add post webpage but for posting a news.

### Add Recommended Websites

It is a webpage where you can add you recommendations in term of websites. It shows a table with at one side, the link of the websites, and at the other side their description. Users can filter websites via searching for specific words in the description.

### Administration Pannel

- A link to a page where you can edit your description in the home page (supports html / markdown) 
- A link to a page where you can edit the comment filters. The comment filters is used when a comment is submitted (in the post section) to forbid the it if it contains certain terms added in the comment filters.
- A link to a page where you can add an ip you want to block from your websites
- A link to a page where you can find the ip of a user that have created an account and potentially block it from you websites.

## Features

The comments does not support any html tags apart from &ltbr/&gt and the markdown tags for bold and italic characters.
While the description and post (news and blog) fuly support all html, even local files link with the following path `../../static/files/filename`

The comments are ditable by the user who posted it.
The comments can be removed by the administrator.

# Production Server

Works with gunicorn

## Reverse Proxy (recommended)

NGINX

# Installation process

## Git clone

In your home directory create a folder containing all the code code base of this application via `git clone https://julienlargetpiet/flask_app`

## Requirements

Change directory with `cd flask_app`

Install mariadb:

`sudo apt-get install mariadb-server-10.5 pip libmariadb3 libmariadb-dev python3-venv`

Create a python virtual environment named menv
`python3 -m venv menv`

Source it

`. menv/bin/activate`

Install required python libraries

`if [ $(($(dpkg -l | grep ^python3-blinker$ | wc -l) > 0)) -eq 1 ];then sudo apt remove python3-blinker;fi`

`pip install -r requirements.txt`

## Database

### User creation

`mariadb`

Once in the mariadb shell:

`CREATE USER database_username IDENTIFIED BY 'database_password';`

### Grant privileges

`GRANT ALL PRIVILEGES ON blog.* TO database_username;`

### Create database

`CREATE DATABASE blog;`

### Database configuration and admin password

From a bash shell run the following,

`python3 admin_password.py strong_password`


`mariadb -u database_username -p blog < start.sql`

## VPS configuration (Debian 11)

### Gunicorn service

With `systemd`, create a service named `/etc/systemd/system/flask_blog.service`

In order to do that: 

Replace `username` by your username in the vps and the `server_ip` with th ip of your vps.
You can do this manually or with the following command:

`sed s/username/$(whoami)/g -i deployment_files/flask_blog.service` 


`sed s/server_ip/$(curl ipinfo.io/ip)/g -i deployment_files/flask_blog.service`

Now, copy the file in `/etc/systemd/system/flask_blog.service`

At the 13th line of `flask_blog.service`, you can increase the numbers of workers based on the number of cores on your vps, the number of cores should equal to 2xnumber_cores + 1, so 3 in the case of the vps having one core.

Start this service:

`sudo systemctl start --now flask_blog.service`

See if it works fine:

`sudo systemctl status flask_blog.service`

If no problem, enable this service:

`sudo systemctl enable flask_blog.service`

### NGINX (1.18.0)

Supposing you have bought a domain name and redirect it to your server via host company pannel or another method.

`sudo apt-get install nginx`

Normally the file `/etc/nginx/nginx.conf` is already filled.
You just have to copy `deployment_files/my-server.conf` to `/etc/nginx/sites-available/my-server.conf`

`cp deployment_files/my-server.conf /etc/nginx/sites-available/my-server.conf`

If you want to activate **https**, you can do this with `certbot`

`sudo apt-get install python3-certbot-nginx`

`sudo certbot certonly --webroot -w /var/www/html -d domain_name`

Activate service

`sudo systemctl start --now nginx`

See if alright

`sudo systemctl status nginx`

If so, enable this service

`sudo systemctl enable nginx`

Now, you can reboot to see if the service starts normally after booting your server

`sudo reboot`

# Security

Passwords are encrypted in the database by **aes**

Warning, change the value of the:

`app.config["allow_com"]` and `app.config["forbid_com"]`


As well as those store in `templates/post.html`, rows 37 and 41. 

# Administration

As an administrator, you can grant privileges separately on chosen users.
The privileges are to delete comments, to post in the blog feed, to post in the news feed, to post in the recommendation feed and to see user ip and ip ban it.
You can **grant** privileges by clicking on the related link in the administration pannel page.
You can grant privileges on multiple users once by separating usernames by a comma.
You can **revoke** privileges by clicking on the related link on the administration pannel page.
You can revoke privileges on multiple users once by separating usernames by a comma.
You can see the privileges status of all users by clicking on the related link on the administration pannel page.

# Bash commands used for the README

All the bash command have been used under the bash version **5.2.32**, but should work under all versions.






