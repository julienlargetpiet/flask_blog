import sys
import os
from werkzeug.security import generate_password_hash

passwd = sys.argv[1]
passwd = generate_password_hash(passwd)
to_add = "INSERT INTO users (username, password, ip) VALUE ('admin', 'X', 'ip');".replace("X", passwd)
os.system(f'echo "{to_add}" >> start.sql')




