import rarfile
import time; import os
from termcolor import colored
import colorama
from getpass import getuser
colorama.init()

correctPath = False
rarfile.UNRAR_TOOL = "UnRAR.exe"

BANNER1 = colored('''
   ██▀███   ▄▄▄       ██▀███   ███▄    █  ██▓ ███▄    █  ▄▄▄██▀▀▀▄▄▄
  ▓██ ▒ ██▒▒████▄    ▓██ ▒ ██▒ ██ ▀█   █ ▓██▒ ██ ▀█   █    ▒██  ▒████▄
  ▓██ ░▄█ ▒▒██  ▀█▄  ▓██ ░▄█ ▒▓██  ▀█ ██▒▒██▒▓██  ▀█ ██▒   ░██  ▒██  ▀█▄
  ▒██▀▀█▄  ░██▄▄▄▄██ ▒██▀▀█▄  ▓██▒  ▐▌██▒░██░▓██▒  ▐▌██▒▓██▄██▓ ░██▄▄▄▄██
  ░██▓ ▒██▒ ▓█   ▓██▒░██▓ ▒██▒▒██░   ▓██░░██░▒██░   ▓██░ ▓███▒   ▓█   ▓██▒
  ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ ░▓  ░ ▒░   ▒ ▒  ▒▓▒▒░   ▒▒   ▓▒█░
    ░▒ ░ ▒░  ▒   ▒▒ ░  ░▒ ░ ▒░░ ░░   ░ ▒░ ▒ ░░ ░░   ░ ▒░ ▒ ░▒░    ▒   ▒▒ ░
    ░░   ░   ░   ▒     ░░   ░    ░   ░ ░  ▒ ░   ░   ░ ░  ░ ░ ░    ░   ▒
     ░           ░  ░   ░              ░  ░           ░  ░   ░        ░  ░''', 'blue')
BANNER2 = colored('''             -------------------------------------------------''', 'blue')
BANNER3 = colored('''             || RARNinja: The RAR Password Cracking Utility ||''', 'red')
BANNER4 = colored('''             -------------------------------------------------''', 'blue')


def printBanner():
    print(BANNER1), print(BANNER2), print(BANNER3), print(BANNER4)


def progress():
    clrscr()
    found = False
    with open(dictionary, "r") as file:
        for tries, line in enumerate(file):
            password = str(line).strip()
            try:
                with rarfile.RarFile(RAR, "r") as rar:
                    rar.extractall(path="./Extracted/", pwd=password)
                    print(colored(f"\nCracked and extracted! Password: {password}", "green"))
                    found = True
                    break
            except:
                print(f"Incorrect password tried: {password}")
                continue
    return(found, tries)


def noProgress():
    clrscr()
    found = False
    print("\nWorking...", end='')
    with open(dictionary, "r") as file:
        for tries, line in enumerate(file, start=1):
            password = str(line).strip()
            try:
                with rarfile.RarFile(RAR, "r") as rar:
                    rar.extractall(path="./Extracted/", pwd=password)
                    print(colored(f" Cracked and extracted! Password: {password}", "green"))
                    found = True
                    break
            except:
                continue
    return(found, tries)


def clrscr():
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        _ = os.system('cls')
    printBanner()


############### Main ###############

if __name__ == "__main__":

    printBanner()

    try:

        while (True):
      
            RAR = input("\nEnter Rute RAR file here: ")
            user=getuser()
            syst=os.path.exists("/data/data/com.termux/files/")
            if syst == True:
                output="/data/data/com.termux/files/home/Hash_crack/wordlist.txt"
            else:
                 output=f"/home/{user}/Hash_crack/wordlist.txt"
            
            dictionary=output

            if (os.path.isfile(RAR) is True and os.path.isfile(dictionary) is True):
                break
            else:
                clrscr()
                print("\nWrong route or non-existent wordlist . Try again.\n")
                continue

        while (True):
            print("\nShow progress?")
            print("1. Yes (slower)\n2. No (faster)")
            progressPrompt = input("\nSelect option number (Default = No): ") or "2"

            if (progressPrompt == "1"):
                start = time.time()
                found, tries = progress()
                completionTime = time.time() - start
                break

            elif (progressPrompt == "2"):
                start = time.time()
                found, tries = noProgress()
                completionTime = time.time() - start
                break

            else:
                clrscr()
                print("\nInvalid entry. Choose either option 1 or 2. Try again.\n")
                continue

        if found:
            try:
                rate = (int(tries) // completionTime)
                print(f"\n\nThe task completed successfully in {completionTime} seconds. (at ~{rate} tries/sec)")
                print("Press any key to exit.")
                input()

            except ZeroDivisionError:
                print("\n\nThe task completed successfully in zero seconds.")
                print("Press any key to exit.")
                input()
        else:
            print(colored(f" All lines in {dictionary} tried and exhausted (password not found), You may try another dictionary file.", "red"))
            print("\nPress any key to exit.")
            input()
    except KeyboardInterrupt:
        clrscr()
        print("\nCTRL ^C\n\nThrew a wrench in the works.")
        print("Press Enter to exit.")
        input()
