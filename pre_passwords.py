import os
import random
lst = "azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890"
for I in range(1, 6):
    cur_mdp = ""
    for i in range(0, 15):
        cur_mdp += random.choice(lst)
    os.system(f"sed s/to_replace{I}/{cur_mdp}/ -i app.py")

lst_to_mv = ["filters_com.csv", "banned_usernames.csv", "blacklist.csv"]
for I in range(0, 3):
    cur_mdp = ""
    for i in range(0, 15):
        cur_mdp += random.choice(lst)
    os.system(f"sed s/to_replace{I + 6}/{cur_mdp}/ -i app.py")
    os.system(f"mv {lst_to_mv[I]} static/csvs/{cur_mdp}")



