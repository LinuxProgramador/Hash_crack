#!/usr/bin/python3

from string import ascii_lowercase, digits, ascii_uppercase
from time import sleep
from itertools import product
from sys import exit
from Crypto.Hash import RIPEMD160, MD4
from hashlib import md5, sha1, sha224, sha384, sha256, sha512, sha3_256, sha3_224, sha3_384, sha3_512, blake2s, blake2b, shake_128, shake_256
from passlib.hash import sha256_crypt, sha512_crypt
from bcrypt import checkpw
from hashlib import pbkdf2_hmac

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
    'length_bcrypt': 60,
    'length_md5': 32,
    'length_sha1': 40,
    'length_sha224': 56,
    'length_sha256': 64,
    'length_sha384': 96,
    'length_sha512': 128,
}

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
    print(f"[✓] Password Found: {password}")
    exit(2)

def validation(many_hash, hash_input, password, wpa_psk, ssid):
    """Validates if the hash is equal to the encrypted password."""
    if many_hash.lower() == hash_input.lower():
        auxiliary_crack(password, wpa_psk, ssid)
    else:
        if is_fast_mode != "y":
            print(f"[*] Trying password: {password}")

def crack(count, hash_input, select, wait_time):
    """Attempts to crack a given hash by brute force using various hashing algorithms."""
    ssid = ''
    wpa_psk = False
    for password in brute_force():
        data = password.encode()

        if count == 300000 and wait_time == "y":
            count = 0
            sleep(15)
            
        if select == "MySQL 5.X":
            password_bytes = password.encode('utf-8')
            hash_bytes = sha256(password_bytes).digest()
            validation("*" + hash_bytes.hex().upper(), hash_input, password, wpa_psk, ssid)
        elif select == "NTLM":
            password_utf16 = password.encode('utf-16le')
            hash = MD4.new()
            hash.update(password_utf16)
            validation(hash.hexdigest(), hash_input, password, wpa_psk, ssid)
        elif select == "md5":
            encryption = md5(password.encode("utf-8")).hexdigest()
            validation(encryption, hash_input, password, wpa_psk, ssid)
        elif select == "shake-256":
            hash1 = shake_256(data).hexdigest(int(len(hash_input) / 2))
            validation(hash1, hash_input, password, wpa_psk, ssid)
        elif select == "shake-128":
            shake = shake_128()
            shake.update(data)
            calculated_hash = shake.digest(len(bytes.fromhex(hash_input))).hex()
            validation(calculated_hash, hash_input, password, wpa_psk, ssid)
        elif select in ["sha256crypt", "sha512crypt"]:
            if hashes[select].verify(password, hash_input):
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select == "bcrypt":
            if checkpw(data, bytes(hash_input, encoding="utf-8")):
                auxiliary_crack(password, wpa_psk, ssid)
            elif is_fast_mode != "y":
                print(f"[*] Trying password: {password}")
        elif select in hashes:
            encryption = hashes[select](password.encode("utf-8")).hexdigest()
            validation(encryption, hash_input, password, wpa_psk, ssid)
        elif select == "ripemd-160":
            RIPEMD = RIPEMD160.new()
            RIPEMD.update(data)
            validation(RIPEMD.hexdigest(), hash_input, password, wpa_psk, ssid)

        count += 1

    print("[X] Password not found!")
    exit(2)

def crack_wpa_psk(count, hash_input, wait_time):
    """Performs a brute-force attack on a WPA-PSK hash using PBKDF2-HMAC-SHA1."""
    ssid = input("Enter the SSID: ").strip()
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

def cracking_selection(count, hash_input, hash, wait_time, hash_algorithm_map):
    """Allows the user to choose which hash to crack."""
    valid_hashes = {
        "sha256crypt": "sha256crypt",
        "sha512crypt": "sha512crypt",
        "bcrypt": "bcrypt",
        "MySQL 5.X":"MySQL 5.X"
    }
    select = valid_hashes.get(hash, None)

    if select:
        crack(count, hash_input, select, wait_time)
    else:
        select = input("option: ").strip()
        if select in hash_algorithm_map and "wpa-psk" == hash_algorithm_map[select]:
            crack_wpa_psk(count, hash_input, wait_time)
        elif select in hash_algorithm_map:
            select = hash_algorithm_map.get(select, None)
            crack(count, hash_input, select, wait_time)
        else:
            print("You did not enter the requested data!")
            exit(2)

def main(count):
    """Identifies the hash type based on length and format, then attempts to crack it."""
    global is_fast_mode

    try:
        print("INFO: \"bcrypt/shacrypt/wpa-psk/ripemd-160/ntlm\" hashes tend to take longer to decrypt.")
        is_fast_mode = input("Do you want to use the fast crack version (y/n): ").strip().lower()
        wait_time = input("Do you want to prevent overheating the processor? (y/n): ").strip().lower()
        hash_input = input("Enter the hash to decrypt: ").strip()

        if len(hash_input) == hashes['length_md5']:
            print("Type hash:\n1)- md5\n2)- NTLM\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "md5", "2": "NTLM", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_sha1']:
            print("Type hash:\n1)- sha1\n2)- ripemd-160\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha1", "2": "ripemd-160", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_sha224']:
            print("Type hash:\n1)- sha224\n2)- sha3_224\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha224", "2": "sha3_224", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_sha384']:
            print("Type hash:\n1)- sha384\n2)- sha3_384\n3)- shake-128\n4)- shake-256")
            hash_algorithm_map = {"1": "sha384", "2": "sha3_384", "3": "shake-128", "4": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_sha256']:
            print("Type hash:\n1)- sha256\n2)- sha3_256\n3)- blake2s\n4)- wpa-psk\n5)- shake-128\n6)- shake-256")
            hash_algorithm_map = {"1": "sha256", "2": "sha3_256", "3": "blake2s", "4": "wpa-psk", "5": "shake-128", "6": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_sha512']:
            print("Type hash:\n1)- sha512\n2)- sha3_512\n3)- blake2b\n4)- shake-128\n5)- shake-256")
            hash_algorithm_map = {"1": "sha512", "2": "sha3_512", "3": "blake2b", "4": "shake-128", "5": "shake-256"}
            cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
        elif len(hash_input) == hashes['length_bcrypt'] and any(v in hash_input[0:5] for v in ["2a$", "2b$", "2y$"]):
            cracking_selection(count, hash_input, "bcrypt", wait_time, "")
        elif "$5" in hash_input[0:2]:
            cracking_selection(count, hash_input, "sha256crypt", wait_time, "")
        elif "$6" in hash_input[0:2]:
            cracking_selection(count, hash_input, "sha512crypt", wait_time, "")
        elif "*" in hash_input[0:1]:
             cracking_selection(count, hash_input, "MySQL 5.X", wait_time, "")
        else:
            if hash_input:
                consultation = input("The entered hash can be \"shake-128 - shake-256\" (y/n): ").strip().lower()
                if consultation == "y":
                    print("Type hash:\n1)- shake-128\n2)- shake-256")
                    hash_algorithm_map = {"1": "shake-128", "2": "shake-256"}
                    cracking_selection(count, hash_input, "", wait_time, hash_algorithm_map)
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

if __name__ == "__main__":
    main(0)

__status__ = "Finish"
