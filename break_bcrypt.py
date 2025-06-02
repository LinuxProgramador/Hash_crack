#!/usr/bin/python3

from multiprocessing import Process, Queue, Event, cpu_count
from bcrypt import checkpw
from time import sleep
from os import system, path
from tqdm import tqdm
import sys


def get_encoder():
    print("INFO: For compatibility with special characters, choose encoder:")
    print("1) latin-1\n2) utf-8")
    return "latin-1" if input("option: ").strip() == "1" else "utf-8"


def check_bcrypt_segment(wordlist, target_hash, encoder, found, queue, progress_queue, wait_time):
    if wait_time == "y":
        sleep(0.15)
    for word in wordlist:
        if found.is_set():
            return
        word = word.strip()
        try:
            if checkpw(word.encode(encoder), target_hash.encode(encoder)):
                queue.put(f"\n[+] Key found: {word}")
                found.set()
                return
        except Exception:
            pass
        progress_queue.put(1)


def load_wordlist(path, encoder):
    try:
        with open(path, "r", encoding=encoder, errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {path}")
        sys.exit(1)

def main():
    encoder = get_encoder()
    sleep(1)
    system("clear")

    dic_path = input("Enter the path to your optimized dictionary: ").strip()
    size_mb = path.getsize(dic_path) / (1024 * 1024)

    if size_mb > 20.0:
        print("Maximum dictionary size limit exceeded, supported ranges 20MB or less")
        sys.exit(0)

    target_hash = input("Enter the bcrypt hash: ").strip()
    wait_time = input("Prevent CPU overheating? (y/n): ").strip().lower()

    wordlist = load_wordlist(dic_path, encoder)
    if not wordlist:
        print("[!] Empty wordlist.")
        sys.exit(1)

    total_words = len(wordlist)
    num_cores = cpu_count()
    print(f"[*] Detected {num_cores} CPU cores. Distributing workload...")

    chunk_size = total_words // num_cores
    chunks = [wordlist[i:i + chunk_size] for i in range(0, total_words, chunk_size)]

    if len(chunks) > num_cores:
        chunks[num_cores - 1].extend(chunks[num_cores])
        chunks = chunks[:num_cores]

    found = Event()
    queue = Queue()
    progress_queue = Queue()

    processes = [
        Process(target=check_bcrypt_segment, args=(
            chunk, target_hash, encoder, found, queue, progress_queue, wait_time))
        for chunk in chunks
    ]

    for p in processes:
        p.start()

    try:
        with tqdm(total=total_words, desc="Cracking", ncols=70) as pbar:
            while any(p.is_alive() for p in processes):
                while not progress_queue.empty():
                    progress_queue.get()
                    pbar.update(1)
                while not queue.empty():
                    print(queue.get())
                    found.set()
                if found.is_set():
                    for p in processes:
                        p.terminate()
                    break
                sleep(0.1)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        for p in processes:
            p.terminate()
        sys.exit(1)

    for p in processes:
        p.join()

    while not queue.empty():
        print(queue.get())

    if not found.is_set():
        print("[-] Key not found in dictionary.")
        sys.exit(1)

if __name__ == "__main__":
    main()


__status__ = "beta"
