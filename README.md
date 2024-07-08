# flask_blog

A personnal blog website built with the Flask Framework.

## WebPages Architecture

### Home webpage

Is the first webpage a user will encounter entering your websites.
It shows:

If you are only a user:

- a link to the **blog post feed**
- a link to the **news feed**
- a link to your **recommendations**

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

### News post

It is a webpage where a news post is, comments are not possible on the news post, but you can edit a news (which will be notifiable by anyone).

### Add Post

It is a webpage where you can write your news post in **html and/or markown, you can add filest with the path `../../static/files/filename`**

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

Nginx


