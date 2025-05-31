#!/usr/bin/python3

from string import ascii_lowercase, digits, ascii_uppercase
from time import sleep
from itertools import product
from sys import exit
from Crypto.Hash import RIPEMD160, MD4
from hashlib import md5, sha1, sha224, sha384, sha256, sha512, sha3_256, sha3_224, sha3_384, sha3_512, blake2s, blake2b, shake_128, shake_256
from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt, apr_md5_crypt, msdcc2, phpass
from bcrypt import checkpw
from hashlib import pbkdf2_hmac,algorithms_available,new,scrypt
from base64 import b64encode,b64decode
from gmssl import sm3,func
from whirlpool import new as wpl
from argon2 import PasswordHasher

hashes = {
    'sha1': sha1,
    'sha224': sha224,
    'sha384': sha384,
    'sha256': sha256,
    'sha512': sha512,
    'sha3_224': sha3_224,
    'sha3_384': sha3_384,
    'sha3_256': sha3_256,
    'sha3_512': sha3_512,
    'blake2b': blake2b,
    'blake2s': blake2s,
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt,
    'md5crypt': md5_crypt,
    'apr1': apr_md5_crypt,
    'DCC2': msdcc2,
    'phpass':phpass,
    'length_bcrypt': 60,
    'length_md5': 32,
    'length_sha1': 40,
    'length_sha224': 56,
    'length_sha256': 64,
    'length_sha384': 96,
    'length_sha512': 128,
}
validation_argon = False

def generate_combinations(characters, min_length, max_length):
    """Generates and yields buffered combinations of characters within the specified length range."""
    block_size = 512 * 1024
    buffer = []
    buffer_size = 0

    for r in range(min_length, max_length + 1):
        for combo in product(characters, repeat=r):
            combo_str = ''.join(combo)
            combo_bytes = combo_str.encode()
            combo_size = len(combo_bytes)

            if buffer_size + combo_size > block_size:
                yield buffer
                buffer = []
                buffer_size = 0

            buffer.append(combo_str)
            buffer_size += combo_size

    if buffer:
        yield buffer

def brute_force():
    """Prompts the user to exclude character sets, then generates and prints random keys for a specified number of attempts."""
    print("Enter the characters to use:")
    print("1) Numbers\n2) Uppercase Letters\n3) Lowercase Letters\n4) Symbols")
    option = input("option: ").strip().replace(" ", "")
    option = list(option)

    char_sets = {
        "3": ascii_lowercase,
        "2": ascii_uppercase,
        "1": digits,
        "4": "/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\"
    }

    try:
      characters = ''.join([char_sets[o] for o in option])
      if not characters:
        raise KeyError
    except KeyError:
        print("Invalid input. Default characters will be set!")
        characters = ascii_lowercase + ascii_uppercase + digits + "/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\"
        
    try:
        min_length = int(input("Key minimum length: "))
        max_length = int(input("Key maximum length: "))
    except ValueError:
        print("Invalid input. The default length will be set.")
        min_length, max_length = 8, 9
        sleep(3)

    if min_length > max_length:
        min_length, max_length = max_length, min_length

    for block in generate_combinations(characters, min_length, max_length):
        for combo in block:
            yield combo

def auxiliary_crack(password, wpa_psk, ssid):
    """Helper function that will show the correct key."""
    print("\n{***********************SUCCESS***********************}")
    if wpa_psk:
        print(f"[✓] SSID: {ssid}")
    print(f"[✓] Password Found: {password.strip()}")
    exit(2)

def validation(many_hash, hash_input, password, wpa_psk, ssid):
    """Validates if the hash is equal to the encrypted password."""
    if many_hash.lower() == hash_input.lower():
        auxiliary_crack(password, wpa_psk, ssid)
    else:
        if is_fast_mode != "y":
            print(f"[*] Trying password: {password.strip()}")

def crack(count, hash_input, select, wait_time):
    """Attempts to crack a given hash by brute force using various hashing algorithms."""
    ssid = ''
    wpa_psk = False
    for password in brute_force():
        data = password.encode()

        if select == "argon2id" and count == 4 and wait_time == "y":
            count = 0
            sleep(1)
        elif count == 300000 and wait_time == "y":
            count = 0
            sleep(15)
            
        if select == "MySQL 5.X":
            hash_bytes = sha1(data).digest()
            second_hash_encoding = sha1(hash_bytes).hexdigest().upper()
            validation("*" + second_hash_encoding, hash_input, password, wpa_psk, ssid)
        elif select == "whirlpool":
            wp = wpl(data)
            validation(wp.hexdigest(), hash_input, password, wpa_psk, ssid)
        elif select == "sha256sum":
            password = password + "\n"
            hash_input = hash_input.replace('  -','')
            sha256sum_hash = sha256(password.encode('utf-8')).hexdigest()
            validation(sha256sum_hash, hash_input, password, wpa_psk, ssid)
        elif select == "sha512sum":
            password = password + "\n"
            hash_input = hash_input.replace('  -','')
            sha512sum_hash = sha512(password.encode('utf-8')).hexdigest()
            validation(sha512sum_hash, hash_input, password, wpa_psk, ssid)
        elif select == "sm3":
            supported_hash =  'sm3' if 'sm3' in algorithms_available else ''
            if supported_hash:
               sm3_hash = new('sm3')
               sm3_hash.update(data)
               validation(sm3_hash.hexdigest(), hash_input, password, wpa_psk, ssid)
            else:
               hash_hex = sm3.sm3_hash(func.bytes_to_list(data))
               validation(hash_hex, hash_input, password, wpa_psk, ssid)
        elif select == "NTLM":
            password_utf16 = password.encode('utf-16le')
            hash = MD4.new()
            hash.update(password_utf16)
            validation(hash.hexdigest(), hash_input, password, wpa_psk, ssid)
        elif select == "sha512-256":
            hash_obj = new("sha512_256", data)             
            validation(hash_obj.hexdigest(), hash_input, password, wpa_psk, ssid)
        elif select == "SSHA":
            b64_data = hash_input[6:]
            decoded = b64decode(b64_data)
            digest = decoded[:20]
            salt = decoded[20:]
            hash_obj = sha1(data)
            hash_obj.update(salt)
            if digest.lower() == hash_obj.digest().lower():
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select == "md5":
            encryption = md5(data).hexdigest()
            validation(encryption, hash_input, password, wpa_psk, ssid)
        elif select == "shake-256":
            hash1 = shake_256(data).hexdigest(int(len(hash_input) / 2))
            validation(hash1, hash_input, password, wpa_psk, ssid)
        elif select == "shake-128":
            shake = shake_128()
            shake.update(data)
            calculated_hash = shake.digest(len(bytes.fromhex(hash_input))).hex()
            validation(calculated_hash, hash_input, password, wpa_psk, ssid)
        elif select in ["sha256crypt", "sha512crypt","md5crypt","apr1","phpass"]:
            if hashes[select].verify(password, hash_input):
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select == "DCC2":
            if hashes[select].verify(password, hash_input, user):
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select == "bcrypt":
            if checkpw(data, bytes(hash_input, encoding="utf-8")):
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select in hashes:
            encryption = hashes[select](data).hexdigest()
            validation(encryption, hash_input, password, wpa_psk, ssid)
        elif select == "ripemd-160":
            supported_hash = 'ripemd160' if 'ripemd160' in algorithms_available else ''
            if supported_hash:
                RIPEMD = new("ripemd160", data)
            else:
                RIPEMD = RIPEMD160.new()
                RIPEMD.update(data)
            validation(RIPEMD.hexdigest(), hash_input, password, wpa_psk, ssid)
        elif select in 'argon2id':
              global validation_argon
              ph = PasswordHasher()
              try:
                 ph.verify(hash_input, password)
                 validation_argon = True
                 auxiliary_crack(password, wpa_psk, ssid)
              except KeyboardInterrupt:
                 print("BYE!!")
                 exit(0)
              except:
                 if not validation_argon:
                     if is_fast_mode != "y":
                        print(f"[*] Trying password: {password}")
              finally:
                 if validation_argon:
                    exit(0)
        count += 1

    print("[X] Password not found!")
    exit(2)

def crack_wpa_psk(count, hash_input, wait_time,validation_hash_wpa_dcc2):
    """Performs a brute-force attack on a WPA-PSK hash using PBKDF2-HMAC-SHA1."""
    hash_input = validation_hash_wpa_dcc2[1]
    ssid = validation_hash_wpa_dcc2[0]
    if not ssid:
        print("You did not enter the SSID name!")
        exit(2)

    wpa_psk = True
    for password in brute_force():
        if count == 300000 and wait_time == "y":
            count = 0
            sleep(17)

        if 8 <= len(password) <= 63:
            derived_key = pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
            if derived_key.hex().lower() == hash_input.lower():
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        else:
            print("Passwords do not meet WPA-PSK required lengths (8/63)!")
            exit(2)

        count += 1

    print("[X] Password not found!")
    exit(2)

def cracking_selection(count, hash_input, hash, wait_time, hash_algorithm_map,validation_hash_wpa_dcc2):
    """Allows the user to choose which hash to crack."""
    valid_hashes = {
        "sha256crypt": "sha256crypt",
        "sha512crypt": "sha512crypt",
        "md5crypt":"md5crypt",
        "SSHA":"SSHA",     
        "DCC2":"DCC2",
        "apr1":"apr1",
        "phpass":"phpass",
        "argon2id":"argon2id",
        "wpa-psk":"wpa-psk",
        "bcrypt": "bcrypt",
        "MySQL 5.X":"MySQL 5.X"
    }
    select = valid_hashes.get(hash, None)

    if select:
        if select == "wpa-psk":
            crack_wpa_psk(count, hash_input, wait_time,validation_hash_wpa_dcc2)
        elif select == "DCC2":    
           global user
           hash_input = validation_hash_wpa_dcc2[1]
           user = validation_hash_wpa_dcc2[0]
           if not user:
                print("You did not enter the username")
                exit(2)
        crack(count, hash_input, select, wait_time)
    else:
        select = input("option: ").strip()
        if select in hash_algorithm_map:
            select = hash_algorithm_map.get(select, None)   
            crack(count, hash_input, select, wait_time)
        else:
            print("You did not enter the requested data!")
            exit(2)

def main(count):
    """Identifies the hash type based on length and format, then attempts to crack it."""
    global is_fast_mode

    try:
        print("INFO: \"argon2id/dcc2/bcrypt/shacrypt/md5crypt/apr1/wpa-psk/ripemd-160/ntlm/sm3/phpass\" hashes tend to take longer to decrypt.")
        is_fast_mode = input("Do you want to use the fast crack version (y/n): ").strip().lower()
        wait_time = input("Do you want to prevent overheating the processor? (y/n): ").strip().lower()
        hash_input = input("Enter the hash: ").strip()
        validation_hash_wpa_dcc2 = hash_input.split(':') if hash_input.count(':') == 1 else list('00')

        if len(hash_input) == hashes['length_md5']:
            print("Type hash:\n1)- md5\n2)- NTLM\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "md5", "2": "NTLM", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_sha1']:
            print("Type hash:\n1)- sha1\n2)- ripemd-160\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha1", "2": "ripemd-160", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_sha224']:
            print("Type hash:\n1)- sha224\n2)- sha3_224\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha224", "2": "sha3_224", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_sha384']:
            print("Type hash:\n1)- sha384\n2)- sha3_384\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha384", "2": "sha3_384", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_sha256'] or hash_input.endswith('-') and len(hash_input) == 67:
            print("Type hash:\n1)- sha256\n2)- sha3_256\n3)- blake2s\n4)- shake-128\n5)- shake-256\n6)- sm3\n7)- sha512-256\n8)- sha256sum")
            hash_algorithm_map = {"1": "sha256", "2": "sha3_256", "3": "blake2s", "4": "shake-128", "5": "shake-256", "6": "sm3", "7": "sha512-256", "8": "sha256sum"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_sha512'] or hash_input.endswith('-') and len(hash_input) == 131:
            print("Type hash:\n1)- sha512\n2)- sha3_512\n3)- blake2b\n4)- shake-128\n5)- shake-256\n6)- whirlpool\n7)- sha512sum")
            hash_algorithm_map = {"1": "sha512", "2": "sha3_512", "3": "blake2b", "4": "shake-128", "5": "shake-256", "6": "whirlpool", "7": "sha512sum"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
        elif len(hash_input) == hashes['length_bcrypt'] and any(v in hash_input[0:5] for v in ["2a$", "2b$", "2y$"]):
            cracking_selection(count, hash_input, "bcrypt", wait_time, "","")
        elif "$5" in hash_input[0:2]:
            cracking_selection(count, hash_input, "sha256crypt", wait_time, "","")
        elif "$6" in hash_input[0:2]:
            cracking_selection(count, hash_input, "sha512crypt", wait_time, "","")
        elif "$1" in hash_input[0:2]:
             cracking_selection(count, hash_input, "md5crypt", wait_time, "","")
        elif "$apr1" in hash_input[0:5]:
             cracking_selection(count, hash_input, "apr1", wait_time, "","")
        elif "{SSHA}" in hash_input[0:7]:
             cracking_selection(count, hash_input, "SSHA", wait_time, "","")
        elif len(validation_hash_wpa_dcc2[1]) == 32:
            cracking_selection(count, hash_input, "DCC2", wait_time, "",validation_hash_wpa_dcc2)
        elif  len(validation_hash_wpa_dcc2[1]) == 64:  
            cracking_selection(count, hash_input, "wpa-psk", wait_time, "",validation_hash_wpa_dcc2)
        elif "*" in hash_input[0:1]:
             cracking_selection(count, hash_input, "MySQL 5.X", wait_time, "","")
        elif "$P$" in hash_input[0:3]:
             cracking_selection(count, hash_input, "phpass", wait_time, "","")
        elif "$argon2id$" in hash_input[0:11]:
             cracking_selection(count, hash_input, "argon2id", wait_time, "","")
        else:
            if hash_input:
                consultation = input("The entered hash can be \"shake-128 - shake-256\" (y/n): ").strip().lower()
                if consultation == "y":
                    print("Type hash:\n1)- shake-128\n2)- shake-256")
                    hash_algorithm_map = {"1": "shake-128", "2": "shake-256"}
                    cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map,"")
                else:
                    print("""\n
 \"The hash entered is of incorrect length or does not comply
 with the standards supported by the script.
 Please verify and try again.\"
                  """ + "\n")
            else:
                print("No hash entered!")

    except KeyboardInterrupt:
        print("BYE!!")
    except ValueError as e:
        print(f"Type error: {e}")
    except IndexError:
        print("Enter the \"DCC2/WPA-PSK\" hash with the user or SSID")

if __name__ == "__main__":
    main(0)

__status__ = "Finish"
