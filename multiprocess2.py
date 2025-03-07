#!/usr/bin/python3

from multiprocessing import Process,Queue,Event
from hashlib import pbkdf2_hmac
from sys import exit, argv
from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt, apr_md5_crypt, msdcc2
from os import path, system
from bcrypt import checkpw
from time import sleep

hashes = {
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt,
    'md5crypt': md5_crypt,
    'DCC2': msdcc2,
    'apr1':apr_md5_crypt
}

def get_encoder():
    print("INFO: For compatibility reasons with certain symbols, choose encoder:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder

def crack(target_hash, word, select, ssid, found, queue, encoder):
    if select == "bcrypt":
        if checkpw(word.encode(), bytes(target_hash, encoding=encoder)):
            queue.put(f"Key found: {word}")
            found.set()
    elif select in hashes:
        if select == 'sha512crypt':
           sleep(0.4)
        if hashes[select].verify(word, target_hash):
            queue.put(f"Key found: {word}")
            found.set()
    elif select == "DCC2":
        if hashes[select].verify(word, target_hash, user):
           queue.put(f"Key found: {word}")
           found.set()
    elif select == "wpa-psk":
        if 8 <= len(word) <= 63:
            derived_key = pbkdf2_hmac('sha1', word.encode(), ssid.encode(), 4096, 32)
            if derived_key.hex().lower() == target_hash.lower():
                queue.put(f"SSID: {ssid}\nKey found: {word}")
                found.set()

def check_hash(rute, target_hash, select, ssid, found, queue, wait_time, encoder, chunk_size=512 * 1024):
    try:
        with open(rute, 'r', encoding=encoder) as file:
            buffer = ""
            while not found.is_set():
                chunk = file.read(chunk_size)
                if wait_time == "y":
                    sleep(15)
                if not chunk:
                    break
                buffer += chunk
                lines = buffer.splitlines()
                buffer = lines[-1] if len(lines) > 1 else ""
                for word in lines[:-1]:
                    crack(target_hash, word, select, ssid, found, queue, encoder)
            if buffer:
                crack(target_hash, buffer.strip(), select, ssid, found, queue, encoder)
    except FileNotFoundError:
        queue.put(f"File not found: {rute}")
    except ValueError as e:
        queue.put(f"Type error: {e}")
    except Exception as e:
        queue.put(f"Error processing {rute}: {e}")

def main():
    try:
        encoder = get_encoder()
        sleep(1)
        system("clear")

        rute1 = input("Enter the path of dictionary -1: ").strip()
        rute2 = input("Enter the path of dictionary -2: ").strip()
        rute3 = input("Enter the path of dictionary -3: ").strip()
        rute4 = input("Enter the path of dictionary -4: ").strip()
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
        target_hash = input("Enter the hash to be decrypted: ").strip()

        if any(v in target_hash[0:5] for v in ["2a$", "2b$", "2y$"]):
            select = "bcrypt"
        elif target_hash.startswith("$5"):
            select = "sha256crypt"
        elif target_hash.startswith("$6"):
            select = "sha512crypt"
        elif target_hash.startswith("$1"):
             select = "md5crypt"
        elif target_hash.startswith("$apr1"):
            select = "apr1"
        elif len(target_hash) == 64:
            select = "wpa-psk"
        else:
            print("You did not enter a valid hash!")
            exit(0)

        if select == "wpa-psk":
            print("INFO: Make sure the keys within the dictionary are approximately 8-63 in length")
            ssid = input("Enter the SSID (if WPA-PSK): ").strip()
            if not ssid:
                print("You did not enter the SSID name")
                exit(0)
        else:
            ssid = None

    except KeyboardInterrupt:
        print()
        exit(0)

    found = Event()
    queue = Queue()

    print("Starting parallel checking..")

    processes = [
        Process(target=check_hash, args=(rute, target_hash, select, ssid, found, queue, wait_time, encoder))
        for rute in [rute1, rute2, rute3, rute4]
    ]

    for process in processes:
        process.start()

    try:
        while any(process.is_alive() for process in processes):
            while not queue.empty():
                print(queue.get())
                found.set()
            if found.is_set():
                for process in processes:
                    process.terminate()
                break
            for process in processes:
                process.join(timeout=1)

        if found.is_set():
            for process in processes:
                process.terminate()

    except KeyboardInterrupt:
        print()
        for process in processes:
            process.terminate()
        exit(0)
    except ValueError as e:
        print(f"Type error: {e}")
        for process in processes:
            process.terminate()
        exit(0)

    while not queue.empty():
        print(queue.get())

    if not found.is_set():
        print("Key not found in the dictionaries.")
        print("Checking completed.")
        exit(1)

    print("Checking completed.")

if __name__ == "__main__":
    main()


__status__ = "Finish"
