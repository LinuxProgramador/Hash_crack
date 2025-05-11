#!/usr/bin/python3

from string import ascii_lowercase, digits, ascii_uppercase
from multiprocessing import Process, Queue, Event
from time import sleep
from itertools import product
from sys import exit
from Crypto.Hash import RIPEMD160, MD4
from hashlib import (
    md5, sha1, sha224, sha384, sha256, sha512,
    sha3_256, sha3_224, sha3_384, sha3_512,
    blake2s, blake2b, shake_128, shake_256,
    pbkdf2_hmac, algorithms_available, new
)
from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt, apr_md5_crypt, msdcc2, phpass
from bcrypt import checkpw
from base64 import b64decode
from gmssl import sm3, func
from whirlpool import new as wpl

hash_algorithms = {
    'sha1': sha1,
    'sha224': sha224,
    'sha384': sha384,
    'sha256': sha256,
    'sha512': sha512,
    'sha3-224': sha3_224,
    'sha3-384': sha3_384,
    'sha3-256': sha3_256,
    'sha3-512': sha3_512,
    'blake2b': blake2b,
    'blake2s': blake2s,
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt,
    'md5crypt': md5_crypt,
    'apr1': apr_md5_crypt,
    'phpass': phpass
}


def generate_word_blocks(config):
    block_limit = 512 * 1024
    buffer, buffer_size = [], 0

    for r in range(config[1], config[2] + 1):
        for combo in product(config[0], repeat=r):
            word = ''.join(combo)
            encoded = word.encode()
            size = len(encoded)

            if buffer_size + size > block_limit:
                yield buffer
                buffer, buffer_size = [], 0

            buffer.append(word)
            buffer_size += size

    if buffer:
        yield buffer


def word_generator(config):
    for block in generate_word_blocks(config):
        for word in block:
            yield word


def hash_worker(config, target_hash, hash_type, stop_event, result_queue, wait_time):
    for word in word_generator(config):
        word = word.strip()
        data = word.encode()

        if stop_event.is_set():
            break

        computed_hash = ''
        
        if wait_time == "y":
             sleep(0.20)

        try:
            if hash_type == "mysql5.X":
                computed_hash = "*" + sha1(sha1(data).digest()).hexdigest().upper()
            elif hash_type == "whirlpool":
                computed_hash = wpl(data).hexdigest()
            elif hash_type == "sha256sum":
                word += "\n"
                target_hash = target_hash.replace('  -', '')
                computed_hash = sha256(word.encode()).hexdigest()
            elif hash_type == "sha512sum":
                word += "\n"
                target_hash = target_hash.replace('  -', '')
                computed_hash = sha512(word.encode()).hexdigest()
            elif hash_type == "sm3":
                if 'sm3' in algorithms_available:
                    h = new('sm3')
                    h.update(data)
                    computed_hash = h.hexdigest()
                else:
                    computed_hash = sm3.sm3_hash(func.bytes_to_list(data))
            elif hash_type == "ntlm":
                h = MD4.new()
                h.update(word.encode('utf-16le'))
                computed_hash = h.hexdigest()
            elif hash_type == "sha512-256":
                computed_hash = new("sha512_256", data).hexdigest()
            elif hash_type == "ssha":
                b64_data = target_hash[6:]
                decoded = b64decode(b64_data)
                digest = decoded[:20]
                salt = decoded[20:]
                h = sha1(data)
                h.update(salt)
                computed_hash = h.digest()
                if computed_hash.lower() == digest.lower():
                    stop_event.set()
                    result_queue.put(word)
                    break
            elif hash_type == "md5":
                computed_hash = md5(data).hexdigest()
            elif hash_type == "shake-256":
                computed_hash = shake_256(data).hexdigest(len(target_hash) // 2)
            elif hash_type == "shake-128":
                s = shake_128()
                s.update(data)
                computed_hash = s.digest(len(bytes.fromhex(target_hash))).hex()
            elif hash_type == "ripemd-160":
                if 'ripemd160' in algorithms_available:
                    computed_hash = new("ripemd160", data).hexdigest()
                else:
                    h = RIPEMD160.new()
                    h.update(data)
                    computed_hash = h.hexdigest()
            elif hash_type == "bcrypt":
                if checkpw(word.encode(), target_hash.encode()):
                    stop_event.set()
                    result_queue.put(word)
                    break
            elif hash_type in hash_algorithms:
                  if hash_type in ['sha512crypt']:
                     sleep(0.02)
                  if hash_type in ['sha256crypt', 'sha512crypt', 'md5crypt', 'apr1', 'phpass']:
                     if hash_algorithms[hash_type].verify(word, target_hash):
                        stop_event.set()
                        result_queue.put(word)
                        break
                  else:
                     computed_hash = hash_algorithms[hash_type](data).hexdigest()
            elif hash_type == "dcc2":
                sleep(0.02)
                if msdcc2.verify(word, target_hash, user=user):
                    stop_event.set()
                    result_queue.put(word)
                    break
            elif hash_type == "wpa":
                if 8 <= len(word) <= 63:
                    derived_key = pbkdf2_hmac('sha1', word.encode(), ssid.encode(), 4096, 32)
                    if derived_key.hex().lower() == target_hash.lower():
                        stop_event.set()
                        result_queue.put(word)
                        break

            if computed_hash.lower() == target_hash.lower():
                stop_event.set()
                result_queue.put(word)
                break

        except Exception:
            continue


def main():
    print('''
 -----------------------------
|     Supported Hash Types    |
 -----------------------------
| md5        | sha1         |
| blake2s    | blake2b      |
| ripemd-160 | bcrypt       |
| sha256crypt| sha512crypt  |
| shake-128  | shake-256    |
| wpa        | ntlm         |
| mysql5.X   | md5crypt     |
| apr1       | dcc2         |
| ssha       | sm3          |
| sha512-256 | phpass       |
| whirlpool  | sha512sum    |
| sha256sum  | sha3-224     |
| sha3-384   | sha3-256     |
| sha3-512   | sha256       |
| sha224     | sha384       |
| sha512     |              |
 ---------------------------
''')
    print("INFO: ONLY RECOMMENDED ON SYSTEMS WITH MORE THAN 4 CORES!!!!!!!\n")
    target_hash = input("Enter the target hash: ").strip()
    hash_type = input("Enter the hash type: ").strip().lower()
    wait_time = input("Do you want to prevent overheating the processor? (y/n): ").strip().lower()
    if hash_type not in hash_algorithms and hash_type not in ["ripemd-160","shake-128","shake-256","md5", "dcc2", "mysql5.X", "whirlpool", "sha256sum", "sha512sum", "sm3", "ntlm", "sha512-256", "ssha", "bcrypt", "wpa"]:
       print("Wrong option!")
       exit(0)

    if not target_hash:
        print("You did not enter the requested hash!")
        exit(0)
        
    global ssid, user
    if hash_type == "wpa":
        ssid = input("Enter the SSID: ").strip()
        if not ssid:
            print("You did not enter the SSID!")
            exit(0)
    elif hash_type == "dcc2":
        user = input("Enter the username: ").strip()
        if not user:
            print("You did not enter the username!")
            exit(0)

    print("INFO: \"Enter the four configuration parameters that will be requested to proceed to decrypt the hash\"")
    config_list = []
    for _ in range(4):
        print("\nChoose character sets to use:")
        print("1) Numbers\n2) Uppercase Letters\n3) Lowercase Letters\n4) Symbols")
        selected = input("Option(s): ").strip().replace(" ","")
        sets = {
            "1": digits,
            "2": ascii_uppercase,
            "3": ascii_lowercase,
            "4": "/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\"
        }

        try:
            characters = ''.join([sets[o] for o in selected if o in sets])
            if not characters:
                raise ValueError
        except ValueError:
            print("Invalid input. Default characters will be used.")
            characters = ascii_lowercase + ascii_uppercase + digits + sets["4"]

        try:
            min_len = int(input("Minimum key length: "))
            max_len = int(input("Maximum key length: "))
        except ValueError:
            print("Invalid input. Defaults will be used (8–9).")
            min_len, max_len = 8, 9

        if min_len > max_len:
            min_len, max_len = max_len, min_len

        config_list.append([characters, min_len, max_len])
        
    stop_event = Event()
    result_queue = Queue()

    try:
        processes = [
            Process(target=hash_worker, args=(config, target_hash, hash_type, stop_event, result_queue, wait_time))
            for config in config_list
        ]

        for proc in processes:
            proc.start()

        while any(p.is_alive() for p in processes):
            if stop_event.is_set():
                print("\n{***************** Success *****************}")
                print(f"[✓] Password found:- {result_queue.get().strip()}")
                break

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Terminating processes...")

    finally:
        if 'processes' in locals():
            for proc in processes:
                if proc.is_alive():
                    proc.terminate()
        exit(0)


if __name__ == "__main__":
    main()

__status__ = "Finish"
