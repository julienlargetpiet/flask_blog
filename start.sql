CREATE TABLE already (username VARCHAR(30), answer BOOLEAN);
CREATE TABLE blog_comments (content LONGTEXT, date_time DATETIME, answer_status INT UNSIGNED, post_title VARCHAR(255), com_id INT UNSIGNED, username VARCHAR(255), real_id INT UNSIGNED, modified BOOLEAN);
CREATE TABLE news (title VARCHAR(255), content LONGTEXT, date_time DATETIME, files_name TINYTEXT, modified BOOLEAN, username VARCHAR(255));
CREATE TABLE posts (date_time DATETIME, text_content LONGTEXT, title VARCHAR(255), tags VARCHAR(255), files_name TINYTEXT, allow_comments TINYINT, modified BOOLEAN, username VARCHAR(255));
CREATE TABLE users (username VARCHAR(16), password VARCHAR(162), ip VARCHAR(32), allow_post BOOLEAN, allow_news BOOLEAN, allow_rm_com BOOLEAN, allow_user_ban BOOLEAN, allow_com_control BOOLEAN);
CREATE TABLE welcome_page (description MEDIUMTEXT, recommends INT UNSIGNED);
CREATE TABLE recom (http_link TINYTEXT, tags TINYTEXT);
INSERT INTO welcome_page (description, recommends) VALUE ('description', 0);
INSERT INTO users (username, password, ip) VALUE ('admin', 'password', 'ip');
