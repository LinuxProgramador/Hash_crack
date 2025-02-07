#!/usr/bin/python3

from string import ascii_lowercase, digits, ascii_uppercase
from time import sleep
from itertools import product
from sys import exit
from Crypto.Hash import RIPEMD160,MD4
from hashlib import md5, sha1, sha224, sha384, sha256, sha512, sha3_256, sha3_224, sha3_384, sha3_512, blake2s, blake2b, shake_128, shake_256
from passlib.hash import sha256_crypt, sha512_crypt
from bcrypt import checkpw
from hashlib import pbkdf2_hmac


hashes = {
    'sha1':sha1,
    'sha224':sha224,
    'sha384':sha384,
    'sha256':sha256,
    'sha512':sha512,
    'sha3_224':sha3_224,
    'sha3_384':sha3_384,
    'sha3_256':sha3_256,
    'sha3_512':sha3_512,
    'blake2b':blake2b,
    'blake2s':blake2s,
    'sha256crypt':sha256_crypt,
    'sha512crypt':sha512_crypt,
    'length_bcrypt':60,
    'length_md5':32,
    'length_sha1':40,
    'length_sha224':56,
    'length_sha256':64,
    'length_sha384':96,
    'length_sha512':128,
    }
count = 0

def brute_force():
    '''
      Prompts the user to exclude character sets, then generates and prints random keys for a specified number of attempts
    '''
    print("Enter the characters to use (ENTER THE NUMBERS CLOSELY):")
    print("1) Numbers\n2) Uppercase Letters\n3) Lowercase Letters\n4) Symbols")
    option = list(input("option: "))

    char_sets = {
    "3": ascii_lowercase,
    "2": ascii_uppercase,
    "1": digits,
    "4": "/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\"
    }

    if len(option) == 1:
        characters = char_sets[option[0]]
    elif len(option) == 2:
        characters = char_sets[option[0]] + char_sets[option[1]]
    elif len(option) == 3:
        characters = char_sets[option[0]] + char_sets[option[1]] + char_sets[option[2]]
    else:
        characters = char_sets[option[0]] + char_sets[option[1]] + char_sets[option[2]] + char_sets[option[3]]

    characters = list(characters)
    try:
        max_length = int(input("Key maximum length: "))
    except ValueError:
        print("Invalid input. The default length will be set.")
        max_length = 8
        sleep(3)

    for combo in product(characters, repeat=max_length):
        yield ''.join(combo)



def auxiliary_crack(password,wpa_psk,ssid):
    '''
     Helper function that will show the correct key
    '''
    if wpa_psk:
        print("\n{***********************SUCCESS***********************}")
        print(f"[✓] SSID: {ssid}")
        print(f"[✓] Password Found:- {password}")
        exit(2)
    else:
       print("\n{***********************SUCCESS***********************}")
       print(f"[✓] Password Found:- {password}")
       exit(2)



def validation(many_hash,hash_input,password,wpa_psk,ssid):
       '''
          Validates if the hash is equal to the encrypted password
       '''
       if many_hash.lower() == hash_input.lower():
            auxiliary_crack(password,wpa_psk,ssid)
       else:
            print(f"[*] Trying password:- {password}")



def crack(count,hash_input,select,wait_time):
    '''
      Attempts to crack a given hash by brute force using various hashing algorithms
    '''
    ssid = ''
    wpa_psk = False
    for keywords in brute_force():
        password = keywords
        data = password.encode()

        if count == 300000 and wait_time == "y":
             count = 0
             sleep(8)

        if select == "NTLM":
              password_utf16 = password.encode('utf-16le')
              hash = MD4.new()
              hash.update(password_utf16)
              validation(hash.hexdigest(),hash_input,password,wpa_psk,ssid)

        elif select == "md5":
             encryption = md5(password.encode("utf-8")).hexdigest()
             validation(encryption,hash_input,password,wpa_psk,ssid)

        elif select == "shake-256":
             hash1 = shake_256(data).hexdigest(int(len(hash_input)/2))
             validation(hash1,hash_input,password,wpa_psk,ssid)

        elif select == "shake-128":
             shake = shake_128()
             shake.update(data)
             calculated_hash = shake.digest(len(bytes.fromhex(hash_input))).hex()
             validation(calculated_hash,hash_input,password,wpa_psk,ssid)

        elif select == "sha256crypt" or select == "sha512crypt":
             if hashes[select].verify(password, hash_input):
                auxiliary_crack(password,wpa_psk,ssid)
             else:
                faster(password)

        elif select == "bcrypt":
             if checkpw(data, bytes(hash_input,encoding="utf-8")):
                auxiliary_crack(password,wpa_psk,ssid)
             else:
                faster(password)

        elif select in hashes:
            encryption = hashes[select](password.encode("utf-8")).hexdigest()
            validation(encryption,hash_input,password,wpa_psk,ssid)

        elif select == "ripemd-160":
            RIPEMD = RIPEMD160.new()
            RIPEMD.update(data)
            validation(RIPEMD.hexdigest(),hash_input,password,wpa_psk,ssid)

        elif select in hashes:
             blas2=hashes[select](data).hexdigest()
             validation(blas2,hash_input,password,wpa_psk,ssid)

        else:
            print("Wrong option!")
            exit(2)

        count += 1
    print("[X] Password not found!")
    exit(2)




def crack_wpa_psk(count,hash_input):
    '''
     Performs a brute-force attack on a WPA-PSK hash using PBKDF2-HMAC-SHA1
    '''
    ssid = input("Enter the SSID: ").strip()
    wpa_psk = True
    for keywords in brute_force():
       if count == 300000 and wait_time == "y":
             count = 0
             sleep(8)
       if 8 <= len(keywords) <= 63:
         password = keywords
         derived_key = pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
         if derived_key.hex().lower() == hash_input.lower():
            auxiliary_crack(password,wpa_psk,ssid)
         else:
            print(f"[*] Trying password:- {password}")
       count += 1
    print("[X] Password not found!")
    exit(2)



def cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map):
     '''
        Allows the user to choose which hash to crack
     '''
     valid_hashes = {
     "sha256crypt": "sha256crypt",
     "sha512crypt": "sha512crypt",
     "bcrypt": "bcrypt"
     }
     select = valid_hashes.get(hash, None)
     if select:
          crack(count,hash_input,select,wait_time)
     else:
       select = input("option to decrypt: ").strip()
       if select == "4":
          crack_wpa_psk(count,hash_input)
       elif select == "128":
          select = "shake-128"
          crack(count,hash_input,select,wait_time)
       elif select == "256":
          select = "shake-256"
          crack(count,hash_input,select,wait_time)
       elif select in hash_algorithm_map:
          select = hash_algorithm_map.get(select, None)
          crack(count,hash_input,select,wait_time)
     return


def main(hashes,count):
  '''
   Identifies the hash type based on length and format, then attempts to crack it.
  '''
  hash_algorithm_map = ''
  hash = ''
  try:
    wait_time = input("Do you want to prevent overheating the processor? (y/n): ").strip().lower()
    hash_input=input("Enter the hash to decrypt: ").strip()
    if len(hash_input) == hashes['length_md5']:
             print(f"Type hash:\n1)- md5\n2)- NTLM\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"md5","2":"NTLM","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_sha1']:
             print("Type hash:\n1)- sha1\n2)- ripemd-160\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha1","2":"ripemd-160","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_sha224']:
             print("Type hash:\n1)- sha224\n2)- sha3_224\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha224","2":"sha3_224","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_sha384']:
             print("Type hash:\n1)- sha384\n2)- sha3_384\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha384","2":"sha3_384","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_sha256']:
             print("Type hash:\n1)- sha256\n2)- sha3_256\n3)- blake2s\n4)- wpa-psk\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha256","2":"sha3_256","3":"blake2s","4":"wpa-psk","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_sha512']:
             print("Type hash:\n1)- sha512\n2)- sha3_512\n3)- blake2b\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha512","2":"sha3_512","3":"blake2b","128":"shake-128","256":"shake-256"}
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif len(hash_input) == hashes['length_bcrypt'] and any(v in hash_input[0:5] for v in ["2a$", "2b$", "2y$"]):
             hash = "bcrypt"
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif "$5" in hash_input[0:2]:
             hash = "sha256crypt"
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    elif "$6" in hash_input[0:2]:
             hash = "sha512crypt"
             cracking_selection(count,hash_input,hash,wait_time,hash_algorithm_map)
    else:
        if hash_input:
          print("""\n
 \"The hash entered is of incorrect length or does not comply
 with the standards supported by the script.
 Please verify and try again.\"
                """ + "\n")
        else:
          print("No hash entered!")

  except KeyboardInterrupt:
     print("BYE!!")
  except ValueError as F:
     print(f"Type error: {F}")


if __name__ == "__main__":
     main(hashes,count)
