import sys
from werkzeug.security import generate_password_hash
import re

passwd = sys.argv[1]
print("your password ", passwd, "has a len of ", len(passwd))
passwd = generate_password_hash(passwd)
to_add = re.sub("X", passwd, "INSERT INTO users (username, password, ip) VALUE ('admin', 'X', 'ip');")
cur_file = open("start.sql", "a")
cur_file.write("\n" + to_add + "\n")
cur_file.close()


