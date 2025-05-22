#!/usr/bin/python3

from getpass import getuser
from os import path, remove, system
from shutil import copy
from time import sleep

previous_password = ''
stored = []

if path.exists("/data/data/com.termux/files/"):
    dic_path = "/data/data/com.termux/files/home/Hash_crack/wordlist.txt"
    dic_temp = "/data/data/com.termux/files/home/Hash_crack/temp.txt"
else:
    user = getuser()
    dic_path = f"/home/{user}/Hash_crack/wordlist.txt"
    dic_temp = f"/home/{user}/Hash_crack/temp.txt"

def get_encoder():
    print("INFO: For compatibility reasons with certain symbols, choose your encoder:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder

def create_key_combination():
  try:
    encoder = get_encoder()
    sleep(1)
    system("clear")
    print("This will take time.......")
    global previous_password, stored
    with open(dic_path, 'r', encoding=encoder) as read_file:
        for password in read_file:
            keyclean = password.strip()
            if previous_password:
                stored.append(password.strip() + previous_password)
                stored.append(previous_password + password.strip())
                with open(dic_temp, 'a') as write_file:
                    write_file.write(f"{stored[0]}\n{stored[1]}\n")
            previous_password = keyclean
            stored.clear()


    copy(dic_temp,dic_path)
    remove(dic_temp)
    print("Done!! Now run the main module \"Hasher.py\" again")
  except KeyboardInterrupt:
      print("BYE!!")
      exit(0)
      
create_key_combination()
