import mariadb
import re
import markdown
import os
import math
import random
import csv
import scrypt
import binascii
import magic
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask import Flask, render_template, request, abort, redirect, send_file, session, Markup, url_for, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, validators, TextAreaField
from wtforms.validators import *
from flask_session import Session
from Crypto.Cipher import AES
import datetime
import time

app = Flask(__name__)
app.static_folder = "static"
app.config["SECRET_KEY"] = "secret_key"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_PERMANENT_LIFETIME"] = 43200
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = "static/files/"
app.config["allow_com"] = "Ty67:!?sdfs56k"
app.config["forbid_com"] = "Ft5!Qero56?dl"
app.config["MAX_IP_PER_ACCOUNT"] = 15
Session(app)

params = mariadb.connect(
    user = "julien",
    password = "mamaafricadu78",
    host = "localhost",
    database = "blog_teste",
    autocommit = True
        )
cursor = params.cursor()

socketio = SocketIO(app, cors_allowed_origins = "*")

def comment_filter(value: str) -> str:
    value = " " + value + " "
    r = re.compile("<br/>")
    value = r.sub("¤", value)
    r = re.compile(r'<[A-Z|a-z|0-9|/]+?>')
    value = r.sub('', value)
    r_spe = re.compile("¤")
    value = r_spe.sub("<br/>", value)
    r = re.compile(" ")
    value = r.sub("¤", value)
    r = re.compile("http(s){0,1}://")
    link_found = r.finditer(value)
    code_found = re.search(r'`(.){1,}`', value)
    r_bold = re.compile(r'\*\*([A-Z|a-z|0-9]){1,}\*\*')
    bold_found = r_bold.search(value)
    if not bold_found:
        r_bold = re.compile(r'\_\_([A-Z|a-z|0-9]){1,}\_\_')
        bold_found = r_bold.search(value)
    bold_iter = r_bold.finditer(value)
    r_italic = re.compile(r'([A-Z|a-z|0-9|¤])\*([A-Z|a-z|0-9]){1,}\*([A-Z|a-z|0-9|¤])')
    italic_found = r_italic.search(value)
    if not italic_found:
        r_italic = re.compile(r'([A-Z|a-z|0-9|¤])\_([A-Z|a-z|0-9]){1,}\_([A-Z|a-z|0-9|¤])')
        italic_found = r_italic.search(value)
    italic_iter = r_italic.finditer(value)
    value = " ".join(value)
    value = value.split(" ")
    if code_found:
        idx = [i for i, x in enumerate(value) if x == "`"]
        value[idx[0]] = "<code>"
        value[idx[1]] = "</code>"
        if len(idx) > 2:
            for i in range(2, len(idx)):
                if i % 2 != 0:
                    value[idx[i]] = "<code>"
                else:
                    value[idx[i]] = "</code>"
    if bold_found:
        for i in bold_iter:
            cur_ids = i.span()
            value[cur_ids[0]] = "<b>"
            value[cur_ids[0] + 1] = ""
            value[cur_ids[1] - 2] = "</b>"
            value[cur_ids[1] - 1] = ""
    if italic_found:
        for i in italic_iter:
            cur_ids = i.span()
            value[cur_ids[0] + 1] = "<i>"
            value[cur_ids[1] - 2] = "</i>"
    value[0] = ""
    value[-1] = ""
    dec_val = 0
    for i in link_found:
        cur_id = i.span()[0] - dec_val
        cnt = cur_id
        href_link = ""
        no_stop = True
        while no_stop and value[cnt]:
            if cnt == len(value) - 1:
                no_stop = False
            elif value[cnt] == "¤" or repr(value[cnt]) in ["'\\n'", "'\\r'"]:
                no_stop = False
            else:
                href_link += value[cnt]
                cnt += 1
        del value[cur_id + 1:cnt]
        dec_val += cnt - cur_id - 1
        value[cur_id] = "<a href = '" + href_link + "'>" + href_link + "</a>"
    value = "".join(value)
    value = r_spe.sub(" ", value)
    return Markup(value)

app.jinja_env.filters['comment'] = comment_filter

class file_info():
    image_size = 3 * 1024 * 1024
    max_size = 164 * 1024 * 1024

def PasswordCheck(form, field):
    if len(re.findall("[?!:;&-()\[\]`#@%$*,{}+=\-/]", field.data)) < 3:
        raise validators.ValidationError("Password must have at least 3 special characters")
    if len(re.findall("[0-9]", field.data)) < 3:
        raise validators.ValidationError("Password must have at least 3 numbers")
    if len(re.findall("[a-z]", field.data)) < 3:
        raise validators.ValidationError("Password must have at least 3 lowercase letters")
    if len(re.findall("[A-Z]", field.data)) < 3:
        raise validators.ValidationError("Password must have at least 3 uppercase letters")

def UsernameCheck(form, field):
    if re.search(" ", field.data):
        raise validators.ValidationError("No space allowed in username")
    cursor.execute("SELECT username FROM users;")
    result = cursor.fetchall()
    result = [el[0] for el in result] 
    if field.data in result:
        raise validators.ValidationError("Username already taken")
    result = []
    with open("banned_usernames.csv", "r", encoding = "utf-8") as csv_file:
        cur_f = csv.reader(csv_file)
        for i in cur_f:
            result.append(re.search(i[0], field.data))
    if any(result):
        raise validators.ValidationError("Illegal username")
 
class newuser_form(FlaskForm):
    username = StringField(validators = [
        InputRequired(message = "Username required"),
        validators.Length(3, 16, message = "Must be between 3 and 16 characters"),
        UsernameCheck],
        render_kw = {"placeholder": "username", "style": "width: 10ch", "style": "height: 2ch"})
    password = StringField(validators = [InputRequired(message = "Password required"), 
        validators.Length(12, 30, message = "Must be between 12 and 30 characters"), PasswordCheck], 
        render_kw = {"placeholder": "password"})
    submit = SubmitField("CREATE ACCOUNT")

def UsernameCheckSignIn(form, field):
    cursor.execute("SELECT username FROM users;") 
    result = cursor.fetchall()
    result = [el[0] for el in result]
    if field.data not in result:
        raise validators.ValidationError("Username does not exist")

class signout_form(FlaskForm):
    submit = SubmitField("SIGNOUT")

class signin_form(FlaskForm):
    username = StringField(validators = [InputRequired(message = "Username required"), 
        validators.Length(3, 16, message = "Must be between 3 and 16 characters"),
        UsernameCheckSignIn],
        render_kw = {"placeholder": "username", "style": "width: 10ch", "style": "height: 2ch"})
    password = StringField(validators = [InputRequired(message = "Password required"), 
        validators.Length(12, 30, message = "Must be between 12 and 30 characters")], 
            render_kw = {"placeholder": "password"})
    submit = SubmitField("SIGN IN")

class edit_form(FlaskForm):
    description = TextAreaField(validators = [InputRequired(message = "decription required")], 
            render_kw = {"placeholder": "description", "rows": 45, "cols": 65}) 
    submit = SubmitField("VALIDATE")

def TitleValidationPost(form, field):
    cursor.execute("SELECT title FROM posts")
    result = cursor.fetchall()
    result = [i[0] for i in result]
    if field.data in result:
        raise validators.ValidationError("Title already taken")

class new_post_form(FlaskForm):
    title = StringField(validators = [InputRequired(message = "Title Required"), 
        validators.Length(1, 255),
        TitleValidationPost], 
            render_kw = {"placeholder": "Title"})
    tags = StringField(validators = [validators.Length(min = 0, max = 255)],
            render_kw = {"placeholder": "Tags"})
    n_post_content = TextAreaField(validators = [InputRequired(message = "Title Required")],
            render_kw = {"placeholder": "Post Content", "rows": 45, "cols": 65})
    submit = SubmitField("POST") 

class comment_form(FlaskForm):
    content = TextAreaField(validators = [InputRequired(message = "Content Required")],
            render_kw = {"placeholder": "comment", "rows": 45, "cols": 65})
    submit = SubmitField("COMMENT")

class post_search_form(FlaskForm):
    content = StringField(render_kw = {"placeholder": "Search tags"})
    submit = SubmitField("SEARCH")

def TitleValidationPostNews(form, field):
    cursor.execute("SELECT title FROM news")
    result = cursor.fetchall()
    result = [i[0] for i in result]
    if field.data in result:
        raise validators.ValidationError("Title already taken")

class new_news_post_form(FlaskForm):
    title = StringField(validators = [InputRequired(message = "Title required"), TitleValidationPostNews], 
            render_kw = {"placeholder": "title"}) 
    content = TextAreaField(validators = [InputRequired()],
            render_kw = {"placeholder": "content", "rows": 45, "cols": 65})
    submit = SubmitField("POST")

class news_del_form(FlaskForm):
    submit = SubmitField("DELETE NEWS")

class post_del_form(FlaskForm):
    submit = SubmitField("DELETE POST")

class delete_form(FlaskForm):
    submit = SubmitField("DELETE THIS COMMENT")

def CheckUserExistIp(form, field):
    cursor.execute("SELECT username FROM users;")
    result = cursor.fetchall()
    result = [i[0] for i in result]
    if field.data not in result:
        raise validators.ValidationError("Username not found")

class user_ip_form(FlaskForm):
    user = StringField(validators = [InputRequired(message = "User required"), CheckUserExistIp], 
            render_kw = {"placeholder": "user"})
    submit = SubmitField("ASK")

class after_ip_form(FlaskForm):
    submit = SubmitField("IP BAN")

class recom_form(FlaskForm):
    content = StringField(render_kw = {"placeholder": "search tags"})
    submit = SubmitField("SEARCH")

class add_recom_form(FlaskForm):
    http_link = StringField(validators = [InputRequired()],
            render_kw = {"placeholder": "http(s) link"})
    tags = StringField(validators = [InputRequired()],
            render_kw = {"placeholder": "description / tags"})
    submit = SubmitField("Add Recommendation Websites")

@app.before_request
def block_method():
    ip = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
    with open("blacklist.csv", "r", encoding="UTF-8") as csv_file:
        csv_reader = csv.reader(csv_file)
        for i in csv_reader:
            if i == ip:
                abort(403)
    csv_file.close()
    
@app.route("/", methods = ("POST", "GET"))
def index():
    auth = False
    show_result = False
    user_status = ""
    if "username" in session:
        user_status = session["username"]
        if session["username"] == "admin":
            auth = True
    if request.method == "POST":
        if "username" in session:
            cursor.execute("SELECT answer FROM already WHERE username = ?;", (session["username"],))
            show_result = cursor.fetchall()
            if len(show_result) == 0:
                show_result = True
            elif not show_result[0][0]:
                show_result = True
        if show_result:
            cursor.execute("SELECT recommends FROM welcome_page;")
            nb_rec = cursor.fetchall()[0][0] + 1
            cursor.execute("UPDATE welcome_page SET recommends = ?;", (nb_rec,))
            cursor.execute("INSERT INTO already (username, answer) VALUE (?, TRUE);", (session["username"],))
            return redirect(url_for("index"))
    cursor.execute("SELECT description, recommends FROM welcome_page;")
    result = cursor.fetchall()
    result2 = result[0][1]
    if result[0][0] != None:
        result = markdown.markdown(result[0][0])
    else:
        result = ""
    if "username" in session:
        cursor.execute("SELECT answer FROM already WHERE username = ?;", (session["username"],))
        show_result = cursor.fetchall()
        if len(show_result) == 0:
            show_result = True
        elif not show_result[0][0]:
            show_result = True
    return render_template("index.html", description = result, recommends = result2, show_result = show_result, 
            auth = auth, user_co = user_status)

@app.route("/admin_panel", methods = ("POST", "GET"))
def admin_panel():
    if "username" in session:
        if session["username"] == "admin":
            return render_template("admin_panel.html")
        else:
            return "Not allowed to be here"

@app.route("/see_user_ip", methods = ("POST", "GET"))
def see_user_ip_fun():
    if "username" in session:
        if session["username"] == "admin":
            form = user_ip_form()
            if form.validate_on_submit():
                return redirect(url_for("after_user_ip_fun", user = form.user.data))
            return render_template("see_user_ip.html", form = form)
        else:
            return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/after_user_ip/<user>", methods = ("POST", "GET"))
def after_user_ip_fun(user):
    if "username" in session:
        if session["username"] == "admin":
            form = after_ip_form()
            cursor.execute("SELECT ip FROM users WHERE username = ?;", (user,))
            result = cursor.fetchall()[0][0]
            if form.validate_on_submit():
                cur_f = open("blacklist.csv", "a") 
                cur_f.write("\n" + result + ",")
                cur_f.close
                return redirect(url_for("admin_panel"))
            return render_template("after_user_ip.html", content = result, form = form)
        else:
            return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/edit_ip", methods = ("POST", "GET"))
def edit_ip_fun():
    if "username" in session:
        if session["username"] == "admin":
            if request.method == "POST":
                cur_f = open("blacklist.csv", "w")
                cur_f.write(request.form["content"])
                cur_f.close
                return redirect(url_for("admin_panel"))
            content = ""
            with open("blacklist.csv", "r", encoding = "utf-8") as csv_file:
                cur_f = csv.reader(csv_file)
                for i in cur_f:
                    content += i[0]
                    content += ",\n"
            return render_template("edit_ip.html", content = content)
        return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/comment_filters", methods = ("POST", "GET"))
def comment_filters_fun():
    if "username" in session:
        if session["username"] == "admin":
            if request.method == "POST":
                cur_f = open("filters_com.csv", "w")
                cur_f.write(str(request.form["content"]))
                cur_f.close()
                return redirect(url_for("admin_panel"))
            content = ""
            with open("filters_com.csv", "r", encoding = "utf-8") as csv_file:
                cur_f = csv.reader(csv_file)
                for i in cur_f:
                    content += i[0]
                    content += ",\n"
            return render_template("comments_filters.html", content = content)
        return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/edit", methods = ("POST", "GET"))
def edit():
    if "username" in session:
        if session["username"] == "admin":
            #form = edit_form()
            cursor.execute("SELECT description FROM welcome_page;")
            result = cursor.fetchall()[0][0]
            if request.method == "POST":
                if "file" in request.files:
                    f_info = file_info()
                    if request.content_length > f_info.image_size:
                        return "Image too large"
                    cur_file = request.files["file"]
                    filename = secure_filename(cur_file.filename)
                    cur_path = "static/profile/" + "temp_" + filename
                    cur_file.save(cur_path)
                    if magic.from_file(cur_path, mime = True) not in ["image/jpeg", "image/png", "image/jpg", "image/gif"]:
                        os.remove(cur_path)
                        return "Wrong filetype"
                    else:
                        if os.path.exists("static/profile/profile.jpg"):
                            os.remove("static/profile/profile.jpg")
                        os.rename(cur_path, "static/profile/profile.jpg")
                        image = Image.open("static/profile/profile.jpg")
                        cur_data = list(image.getdata())
                        image2 = Image.new(image.mode, image.size)
                        image2.putdata(cur_data)
                        image2.save("static/profile/profile.jpg")
                if "content" in request.form:
                    cursor.execute("UPDATE welcome_page SET description = ?;", (request.form["content"],))
                return redirect(url_for("index"))
            return render_template("edit.html", content = result)
        else:
            return "Not allowed to be here"
    else:
        return "Not allowed to be here"

@app.route("/new_user", methods = ("POST", "GET"))
def new_user():
    cur_ip = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
    cursor.execute("SELECT COUNT(DISTINCT username) FROM users WHERE ip = ?;", (cur_ip,))
    result = cursor.fetchall()[0][0]
    if result > app.config["MAX_IP_PER_ACCOUNT"]:
        return "Created too many accounts from the same ip adress"
    form = newuser_form()
    if form.validate_on_submit():
        cursor.execute("INSERT INTO users VALUES (?, ?, ?);", 
                (form.username.data, 
                    generate_password_hash(form.password.data), cur_ip))
        session["username"] = form.username.data
        return render_template("account_created.html")
    return render_template("new_user.html", form = form)

@app.route("/signout", methods = ("POST", "GET"))
def signout():
    form = signout_form()
    if form.validate_on_submit():
        del session["username"]
        return redirect(url_for("index"))
    return render_template("signout.html", form = form)

@app.route("/signin", methods = ("POST", "GET"))
def signin():
    form = signin_form()
    if form.validate_on_submit():
        cursor.execute("SELECT password FROM users WHERE username=?;", (form.username.data, ))
        result = cursor.fetchall()[0][0]
        if check_password_hash(result, form.password.data):
            session["username"] = form.username.data
            return redirect(url_for("index"))
        return "Wrong password"
    return render_template("signin.html", form = form)

@app.route("/new_post", methods = ("POST", "GET"))
def new_post():
    if "username" in session:
        if session["username"] == "admin":
            form = new_post_form()
            if form.validate_on_submit():
                all_files_names = ""
                if "files" in request.files:
                    f_info = file_info()
                    if request.content_length > f_info.max_size:
                        return "Files too large"
                    cur_files = request.files.getlist("files")
                    if len(cur_files) > 0:
                        for el in cur_files:
                            if re.search(r"\.", el.filename):
                                cur_filename = app.config["UPLOAD_FOLDER"] + secure_filename(el.filename)
                                cnt = ""
                                if os.path.exists(cur_filename):
                                    cnt = 0
                                    while os.path.exists(app.config["UPLOAD_FOLDER"] + str(cnt) + el.filename):
                                        cnt += 1
                                    cur_filename = app.config["UPLOAD_FOLDER"] + str(cnt) + el.filename
                                el.save(cur_filename)
                                all_files_names += str(cnt) + el.filename + ", "
                                if magic.from_file(cur_filename, mime = True) in ["image/jpeg", "image/png", "image/jpg", "image/gif"]:
                                    image = Image.open(cur_filename)
                                    cur_data = list(image.getdata())
                                    image2 = Image.new(image.mode, image.size)
                                    image2.putdata(cur_data)
                                    image2.save(cur_filename)
                                all_files_names = all_files_names[0:len(all_files_names) - 2]
                if form.tags.data == "":
                    form.tags.data = form.title.data
                cur_time = str(datetime.datetime.now())
                cur_time = cur_time[0:(len(cur_time) - 7)]
                cursor.execute("INSERT INTO posts (date_time, text_content, title, tags, files_name, allow_comments) VALUE (?, ?, ?, ?, ?, TRUE);",
                        (cur_time, form.n_post_content.data, form.title.data, form.tags.data, all_files_names))
                return redirect(url_for("posts_fun", post_title = re.sub(" ", "_", form.title.data)))
            return render_template("new_post.html", form = form)
        else:
            return "Not allowed to be here"
    else:
        return "Not allowed to be here"

@app.route("/all_posts/<post_title>", methods = ("POST", "GET"))
def posts_fun(post_title):
    auth = False
    r = re.compile("_")
    post_title = r.sub(" ", post_title)
    user_name = ""
    if "username" in session:
        user_name = session["username"]
        if session["username"] == "admin":
            auth = True
    form = post_del_form()
    cursor.execute("SELECT allow_comments FROM posts WHERE title = ?;", (post_title,))
    com_status = cursor.fetchall()[0][0]
    if request.method == "POST":
        if app.config["forbid_com"] in request.form:
            cursor.execute("UPDATE posts SET allow_comments = FALSE WHERE title = ?;", (post_title,))
            return redirect(url_for("posts_fun", post_title = post_title))
        if app.config["allow_com"] in request.form:
            cursor.execute("UPDATE posts SET allow_comments = TRUE WHERE title = ?;", (post_title,))
            return redirect(url_for("posts_fun", post_title = post_title))
        if form.validate_on_submit():
            cursor.execute("DELETE FROM posts WHERE title = ?;", (post_title,))
            return redirect(url_for("post_search_fun", page = 0))
    cursor.execute("SELECT date_time, title, text_content, files_name, modified FROM posts WHERE title = ?;", (post_title,))
    res = cursor.fetchall()[0]
    cursor.execute("SELECT content, date_time, answer_status, com_id, username, real_id, modified FROM blog_comments WHERE post_title = ? ORDER BY com_id;", (post_title,))
    res_comments = cursor.fetchall()
    r = re.compile(" ")
    post_title = r.sub("_", post_title)
    return render_template("post.html",
            datetime = res[0], title = res[1], content = markdown.markdown(res[2]), post_title = post_title,
            comments = res_comments, files_names = res[3], auth = auth, form = form, com_status = com_status,
                           user_name = user_name, modified_post = res[4])

@app.route("/delete_com/<real_id>+<post_title>+<com_id>+<com_status>", methods = ("POST", "GET"))
def delete_fun(real_id, post_title, com_id, com_status):
    if "username" in session:
        cursor.execute("SELECT username FROM blog_comments WHERE real_id = ?;", (real_id,))
        result = cursor.fetchall()[0][0]
        if session["username"] in ["admin", result]:
            r = re.compile("_")
            post_title = r.sub(" ", post_title)
            form = delete_form()
            if form.validate_on_submit():
                r = re.compile(" ")
                if com_status == "0":
                    #cursor.execute("SELECT * FROM blog_comments WHERE com_id = ? AND post_title = ?;", (com_id, post_title))
                    cursor.execute("DELETE FROM blog_comments WHERE com_id = ? AND post_title = ?;", (com_id, post_title))
                    post_title = r.sub("_", post_title)
                    return redirect(url_for("posts_fun", post_title = post_title))
                else:
                    cursor.execute("DELETE FROM blog_comments WHERE real_id = ?;", (real_id,))
                    post_title = r.sub("_", post_title)
                    return redirect(url_for("posts_fun", post_title = post_title))
            r = re.compile(" ")
            post_title = r.sub("_", post_title)
            return render_template("delete.html", form = form, post_title = post_title)
        return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/comment_page_post/<post_title>+<answer_status>+<com_id>", methods = ("POST", "GET"))
def comment_page_post_fun(post_title, answer_status, com_id):
    if "username" in session:
        r = re.compile("_")
        post_title = r.sub(" ", post_title)
        form = comment_form()
        if form.validate_on_submit():
            result = []
            with open("filters_com.csv", "r", encoding= "utf-8") as csv_file:
                cur_f = csv.reader(csv_file)
                for i in cur_f:
                    result.append(re.search(i[0], form.content.data))
            if any(result):
                return "Comment not allowed"
            cur_time = str(datetime.datetime.now())
            cur_time = cur_time[0:(len(cur_time) - 7)]
            cursor.execute("SELECT COUNT(*) FROM blog_comments;")
            real_id = cursor.fetchall()[0][0] + 1
            if answer_status == "0":
                cursor.execute("SELECT COUNT(DISTINCT com_id) FROM blog_comments WHERE post_title = ?", (post_title,))
                com_id = cursor.fetchall()[0][0]
                com_id += 1
                cursor.execute("INSERT INTO blog_comments (content, date_time, answer_status, post_title, com_id, username, real_id) VALUE (?, ?, ?, ?, ?, ?, ?)", (form.content.data, cur_time, 0, post_title, com_id, session["username"], real_id))
            else:
                cursor.execute("SELECT post_title FROM blog_comments WHERE post_title = ? AND com_id = ?;", (post_title, com_id))
                cur_res = cursor.fetchall()
                if len(cur_res) > 0:
                    cursor.execute("INSERT INTO blog_comments (content, date_time, answer_status, post_title, com_id, username, real_id) VALUE (?, ?, ?, ?, ?, ?, ?)", (form.content.data, cur_time, 1, post_title, com_id, session["username"], real_id))
                else:
                    return "Response to no comment is not allowed"
            r = re.compile(" ")
            post_title = r.sub("_", post_title)
            return redirect(url_for("posts_fun", post_title = post_title))
        r = re.compile(" ")
        post_title = r.sub("_", post_title)
        return render_template("comment_page_post.html", form = form, post_title = post_title)
    else:
        return "Not connected, not allowed to comment"

@app.route("/post_search/<page>", methods = ("POST", "GET"))
def post_search_fun(page):
    page = int(page)
    form = post_search_form()
    cur_tags = "."
    if request.method == "POST":
        if app.config["forbid_com"] in request.form:
            cursor.execute("UPDATE posts SET allow_comments = FALSE;")
            return redirect(url_for("post_search_fun", page = page))
        if app.config["allow_com"] in request.form:
            cursor.execute("UPDATE posts SET allow_comments = TRUE;")
            return redirect(url_for("post_search_fun", page = page))
        if form.validate_on_submit():
            if form.content.data == "":
                cur_tags = "."
            else:
                r = re.compile(" ")
                cur_tags = r.sub("|", form.content.data)
    cursor.execute("SELECT title, date_time FROM posts WHERE tags RLIKE ? ORDER BY date_time DESC limit ?,?;", (cur_tags, page * 25, 25))
    result = cursor.fetchall()
    r = re.compile(" ")
    title_link = [r.sub("_", i[0]) for i in result]
    auth = False
    if "username" in session:
        if session["username"] == "admin":
            auth = True
    cursor.execute("SELECT allow_comments FROM posts;")
    com_status = cursor.fetchall()
    com_status = all([i[0] for i in com_status])
    if len(result) > 0:
        return render_template("post_search.html", posts = result, page = page, 
                form = form, title_link = title_link, auth = auth, com_status = com_status)
    elif page == 0:
        return "Not that much posts <a href = '../../'>Home</a>"
    else:
        return render_template("not_much_posts.html", page = page)

@app.route("/post_edit/<post_title>", methods = ("POST", "GET"))
def edit_post_fun(post_title):
    if "username" in session:
        if session["username"] == "admin":
            r = re.compile("_")
            post_title = r.sub(" ", post_title)
            cursor.execute("SELECT text_content FROM posts WHERE title = ?;", (post_title,))
            cur_content = cursor.fetchall()
            if len(cur_content) > 0:
                cur_content = cur_content[0][0]
                if request.method == "POST":
                    cursor.execute("UPDATE posts SET text_content = ? WHERE title = ?;", (request.form["content"], post_title))
                    cursor.execute("UPDATE posts SET modified = TRUE WHERE title = ?;", (post_title,))
                    r = re.compile(" ")
                    post_title = r.sub("_", post_title)
                    return redirect(url_for("posts_fun", post_title = post_title))
                return render_template("edit_post.html", content = cur_content, post_title = re.sub(" ", "_", post_title))
            else:
                return "This post does not exist"
        else:
            return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/all_news/<news_title>", methods = ("POST", "GET"))
def news_fun(news_title):
    r = re.compile("_")
    news_title = r.sub(" ", news_title)
    cursor.execute("SELECT title, content, date_time, files_name, modified FROM news WHERE title = ?;", (news_title,))
    res = cursor.fetchall()
    auth = False
    form_del = news_del_form()
    if form_del.validate_on_submit():
        cursor.execute("DELETE FROM news WHERE title = ?", (news_title,))
        return redirect(url_for("news_search_fun", page = 0))
    if "username" in session:
        if session["username"] == "admin":
            auth = True
    if len(res) > 0:
        res = res[0]
        return render_template("news.html", title = re.sub(" ", "_", res[0]), content = res[1], date_time = res[2], 
                auth = auth, form_del = form_del, files_used = res[3], news_modified = res[4])
    else:
        return "This page does not exist or does not exist anymore"

@app.route("/news_search/<page>", methods = ("POST", "GET"))
def news_search_fun(page):
    page = int(page)
    cursor.execute("SELECT title, date_time FROM news ORDER BY date_time DESC limit ?,?;", (page * 25, 25))
    result = cursor.fetchall()
    r = re.compile(" ")
    news_link = [r.sub("_", i[0]) for i in result]
    if len(result) > 0:
        return render_template("news_search.html", news = result, page = page, news_link = news_link)
    elif page == 0:
        return "Not that much news <a href = '../../'>Home</a>"
    else:
        return render_template("not_much_news.html", page = page)

@app.route("/new_news_post", methods = ("POST", "GET"))
def new_news_post():
    if "username" in session:
        if session["username"] == "admin":
            form = new_news_post_form()
            if form.validate_on_submit():
                all_files_names = ""
                if "files" in request.files:
                    f_info = file_info()
                    if request.content_length > f_info.max_size:
                        return "Files too large"
                    cur_files = request.files.getlist("files")
                    all_files_names = ""
                    if len(cur_files) > 0:
                        for el in cur_files:
                            if re.search(r"\.", el.filename):
                                cur_filename = app.config["UPLOAD_FOLDER"] + secure_filename(el.filename)
                                cnt = ""
                                if os.path.exists(cur_filename):
                                    cnt = 0
                                    while os.path.exists(app.config["UPLOAD_FOLDER"] + str(cnt) + el.filename):
                                        cnt += 1
                                    cur_filename = app.config["UPLOAD_FOLDER"] + str(cnt) + el.filename
                                el.save(cur_filename)
                                all_files_names += str(cnt) + el.filename + ", "
                                if magic.from_file(cur_filename, mime = True) in ["image/jpeg", "image/png", "image/jpg", "image/gif"]:
                                    image = Image.open(cur_filename)
                                    cur_data = list(image.getdata())
                                    image2 = Image.new(image.mode, image.size)
                                    image2.putdata(cur_data)
                                    image2.save(cur_filename)
                                all_files_names = all_files_names[0:len(all_files_names) - 2]
                cur_time = str(datetime.datetime.now())
                cur_time = cur_time[0:(len(cur_time) - 7)]
                cursor.execute("INSERT INTO news (title, content, date_time, files_name) VALUE (?, ?, ?, ?);", 
                        (form.title.data, form.content.data, cur_time, all_files_names))
                return redirect(url_for("news_fun", news_title = form.title.data))
            return render_template("new_news_post.html", form = form)
        else:
            return "Not Allowed to be here"
    return "Not Allowed to be here"

@app.route("/news_edit/<news_title>", methods = ("POST", "GET"))
def edit_news_fun(news_title):
    if "username" in session:
        if session["username"] == "admin":
            r = re.compile("_")
            news_title = r.sub(" ", news_title)
            cursor.execute("SELECT content FROM news WHERE title = ?;", (news_title,))
            pre_content = cursor.fetchall()
            if len(pre_content) > 0:
                pre_content = pre_content[0][0] 
                if request.method == "POST":
                    cursor.execute("UPDATE news SET content = ? WHERE title = ?;", (request.form["content"], news_title))
                    cursor.execute("UPDATE news SET modified = TRUE WHERE title = ?;", (news_title,))
                    r = re.compile(" ")
                    news_title = r.sub("_", news_title)
                    return redirect(url_for("news_fun", news_title = news_title))
                return render_template("edit_news.html", news_title = re.sub(" ", "_", news_title), pre_content = pre_content)
            else:
                return "This news does not exist"
        else:
            return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/recommendations_websites", methods = ("GET", "POST"))
def recom_fun():
    form = recom_form()
    cur_tags = "."
    if form.validate_on_submit():
        cur_tags = form.content.data
        r = re.compile(" ")
        cur_tags = r.sub("|", cur_tags)
    cursor.execute("SELECT * FROM recom WHERE tags RLIKE ?;", (cur_tags,))
    result = cursor.fetchall()
    print(result)
    return render_template("recom.html", recoms = result, form = form)

@app.route("/add_recom", methods = ("GET", "POST"))
def add_recom_fun():
    if "username" in session:
        print("ok")
        print(session["username"])
        if session["username"] == "admin":
            form = add_recom_form()
            print("here")
            if form.validate_on_submit():
                print("ici")
                cursor.execute("INSERT INTO recom (http_link, tags) VALUE (?, ?);", ( form.http_link.data, form.tags.data))
                return redirect(url_for("recom_fun"))
            return render_template("add_recom.html", form = form)
        else:
            print("no")
            return "Not allowed to be here"
    return "Not allowed to be here"

@app.route("/edit_com/<real_id>+<post_title>", methods = ("POST", "GET"))
def edit_com_fun(real_id, post_title):
    if "username" in session:
        cursor.execute("SELECT username FROM blog_comments WHERE real_id = ?;", (real_id,))
        result = cursor.fetchall()
        if len(result) > 0:
            result = result[0][0]
        else:
            return "This comment does not exist"
        if session["username"] in ["admin", result]:
            cursor.execute("SELECT content FROM blog_comments WHERE real_id = ?;", (real_id,))
            content = cursor.fetchall()[0][0]
            if request.method == "POST":
                if "content" in request.form:
                    result = []
                    with open("filters_com.csv", "r", encoding= "utf-8") as csv_file:
                        cur_f = csv.reader(csv_file)
                        for i in cur_f:
                            result.append(re.search(i[0], request.form["content"]))
                    if any(result):
                        return "Comment not allowed"
                    cursor.execute("UPDATE blog_comments SET content = ?, modified = TRUE WHERE real_id = ?;", 
                                   (request.form["content"], real_id))
                    return redirect(url_for("posts_fun", post_title = post_title))
            return render_template("edit_com.html", content = content, post_title = post_title)
        else:
            return "Not allowed to be here"
    else:
        return "Not allowed to be here"

if __name__ == "__name__":
    socketio.run(debug = True, threaded = True)

