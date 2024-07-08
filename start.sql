CREATE TABLE already (username VARCHAR(30), answer BOOLEAN);
CREATE TABLE blog_comments (content LONGTEXT, date_time DATETIME, answer_status INT UNSIGNED, post_title VARCHAR(255), com_id INT UNSIGNED, username VARCHAR(255), real_id INT UNSIGNED, modified BOOLEAN);
CREATE TABLE news (title VARCHAR(255), content LONGTEXT, date_time DATETIME, files_name TINYTEXT, modified BOOLEAN);
CREATE TABLE posts (date_time DATETIME, text_content LONGTEXT, title VARCHAR(255), tags VARCHAR(255), files_name TINYTEXT, allow_comments TINYINT, modified BOOLEAN);
CREATE TABLE users (username VARCHAR(16), password VARCHAR(162), ip VARCHAR(32));
CREATE TABLE welcome_page (description MEDIUMTEXT, recommends INT UNSIGNED);
CREATE TABLE recom (http_link TINYTEXT, tags TINYTEXT);
INSERT INTO welcome_page (description, recommends) VALUE ('description', 0);
INSERT INTO users (username VARCHAR(16), password VARCHAR(162), ip VARCHAR(32)) VALUE ('admin', 'password', 'ip');
