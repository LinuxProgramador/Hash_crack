#!/usr/bin/python3

from multiprocessing import Process,Queue,Event
from Crypto.Hash import RIPEMD160, MD4
from hashlib import md5, sha1, sha224, sha384, sha256, sha512, sha3_256, sha3_224, sha3_384, sha3_512, blake2s, blake2b, shake_128, shake_256
from sys import exit, argv
from time import sleep
from os import system
from base64 import b64decode

HASH_ALGORITHMS = {
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
    'length_md5': 32,
    'length_sha1': 40,
    'length_sha224': 56,
    'length_sha256': 64,
    'length_sha384': 96,
    'length_sha512': 128
}

def get_encoder():
    print("INFO: For compatibility reasons with certain symbols, choose your encoder:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder
    
def crack(target_hash, word, select, event, queue):
    data = word.encode()

    if select == "MySQL 5.X":
       password_bytes = word.encode(encoder)
       hash_bytes = sha1(password_bytes).digest()
       second_hash_encoding = sha1(hash_bytes).hexdigest().upper()
       generated_hash =  "*" + second_hash_encoding
    elif select == "ntlm":
        password_utf16 = word.encode('utf-16le')
        hash_obj = MD4.new()
        hash_obj.update(password_utf16)
        generated_hash = hash_obj.hexdigest()
    elif select == "SSHA":
            b64_data = target_hash[6:]
            decoded = b64decode(b64_data)
            digest = decoded[:20]
            salt = decoded[20:]
            hash_obj = sha1(word.encode(encoder))
            hash_obj.update(salt)
            generated_hash =  hash_obj.digest()
            target_hash = digest
    elif select == "md5":
        generated_hash = md5(data).hexdigest()
    elif select in HASH_ALGORITHMS:
        generated_hash = HASH_ALGORITHMS[select](data).hexdigest()
    elif select == "shake-256":
        generated_hash = shake_256(data).hexdigest(len(target_hash) // 2)
    elif select == "shake-128":
        shake = shake_128()
        shake.update(data)
        generated_hash = shake.digest(len(bytes.fromhex(target_hash))).hex()
    elif select == "ripemd-160":
        RIPEMD = RIPEMD160.new()
        RIPEMD.update(data)
        generated_hash = RIPEMD.hexdigest()

    if generated_hash.lower() == target_hash.lower():
        event.set()
        queue.put(word)

def check_hash(file_path, target_hash, select, event, queue, wait_time, chunk_size=512 * 1024):
    try:
        with open(file_path, 'r', encoding=encoder) as file:
            buffer = ""
            while not event.is_set():
                chunk = file.read(chunk_size)
                if wait_time == "y":
                    sleep(10)
                if not chunk:
                    break
                buffer += chunk
                lines = buffer.splitlines()
                buffer = lines[-1] if len(lines) > 1 else ""
                for word in lines[:-1]:
                    crack(target_hash, word, select, event, queue)
            if buffer:
                crack(target_hash, buffer.strip(), select, event, queue)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except ValueError as e:
        print(f"Type error: {e}")
    except Exception as e:
        print(f"Processing error {file_path}: {e}")

def process_files(file_paths, target_hash, select, wait_time):
    event = Event()
    queue = Queue()

    print("Starting parallel checking...")

    processes = [
        Process(target=check_hash, args=(file_path, target_hash, select, event, queue, wait_time))
        for file_path in file_paths
    ]

    for process in processes:
        process.start()

    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        print("Interruption detected. Closing...")
        event.set()
        for process in processes:
            process.terminate()
        exit(0)

    if event.is_set():
        found_word = queue.get()
        print(f"Key found: {found_word}")
    else:
        print("Key not found in any of the dictionaries.")

    print("Checking completed.")

def get_hash_algorithm(target_hash):
    hash_length = len(target_hash)
    if hash_length == HASH_ALGORITHMS['length_md5']:
        return get_hash_selection(["md5", "ntlm", "shake-128", "shake-256"])
    elif hash_length == HASH_ALGORITHMS['length_sha1']:
        return get_hash_selection(["sha1", "ripemd-160", "shake-128", "shake-256"])
    elif hash_length == HASH_ALGORITHMS['length_sha224']:
        return get_hash_selection(["sha224", "sha3_224", "shake-128", "shake-256"])
    elif hash_length == HASH_ALGORITHMS['length_sha384']:
        return get_hash_selection(["sha384", "sha3_384", "shake-128", "shake-256"])
    elif hash_length == HASH_ALGORITHMS['length_sha256']:
        return get_hash_selection(["sha256", "sha3_256", "blake2s", "shake-128", "shake-256"])
    elif hash_length == HASH_ALGORITHMS['length_sha512']:
        return get_hash_selection(["sha512", "sha3_512", "blake2b", "shake-128", "shake-256"])
    elif "{SSHA}" in target_hash[0:7]:
        return "SSHA"
    elif "*" in target_hash[0:1]:
        return "MySQL 5.X"
    else:
        consultation = input("The entered hash can be \"shake-128 - shake-256\" (y/n): ").strip().lower()
        if consultation == "y":
            return get_hash_selection(["shake-128", "shake-256"])
        else:
            print("You did not enter a valid hash!")
            exit(0)

def get_hash_selection(options):
    print("Type hash:")
    for i, option in enumerate(options, 1):
        print(f"{i}) {option}")
    select = input("option: ").strip()
    try:
        return options[int(select) - 1]
    except (IndexError, ValueError):
        print("Invalid selection!")
        exit(0)

if __name__ == "__main__":
    try:
        encoder = get_encoder()
        sleep(1)
        system("clear")

        file_paths = [
            input(f"Enter the path of dictionary -{i + 1}: ").strip()
            for i in range(4)
        ]
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
        target_hash = input("Enter the hash to be decrypted: ").strip()
        select = get_hash_algorithm(target_hash)

        if select in ["ripemd-160", "ntlm"]:
            print(f"{select} tends to take a little longer")

    except KeyboardInterrupt:
        print()
        exit(0)
    except KeyError:
        print("You did not select the hash type!")
        exit(0)
    except ValueError as e:
        print(f"Type error: {e}")
        exit(0)
    except FileNotFoundError as e:
        print(f"Invalid path: {e}")
        exit(0)

    process_files(file_paths, target_hash, select, wait_time)

__status__ = "Finish"
