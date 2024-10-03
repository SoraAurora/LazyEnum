#!/usr/bin/env python3

import subprocess
import sys
import os
import datetime
import threading

# Color constants
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_command(command):
    try:
        return subprocess.check_output(command, shell=True).decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return "Command failed: " + command

def nmap_scan(level, target):
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = f"nmap_scan_{target.replace('.', '-')}_{timestamp}.txt"
    
    # Define the nmap command based on the specified level
    print(f"{CYAN}[*] Nmap Scan for {target} starting...")
    if level == 'light':

        nmap_result = run_command(f"nmap -sS -p- -T5 {target} -oN {output_file}")

        print(f"{GREEN}[+] Nmap results saved to {output_file}{WHITE}")

    elif level == 'medium':

        nmap_result = run_command(f"nmap -sS -p- -T5 {target}")
        ports = extract_ports(nmap_result)
      
        if ports:
            print(f"{GREEN}[+] Open Ports: {ports}{WHITE}")
            port_string = ",".join(ports)
            nmap_result = run_command(f"nmap -sS -p{port_string} -T5 --script vuln -O {target} -oN {output_file}")
            print(f"{GREEN}[+] Nmap results saved to {output_file}{WHITE}")
        else:
            print(f"{WHITE}[!] No open ports found.{WHITE}")

    elif level == 'heavy':

        nmap_result = run_command(f"nmap -sS -p- -T5 {target}")
        ports = extract_ports(nmap_result)
        if ports:
            print(f"{GREEN}[+] Open Ports: {ports}{WHITE}")
            port_string = ",".join(ports)
            nmap_result = run_command(f"nmap -sS -p{port_string} -T5 -sV --script vuln -O {target} -oN {output_file}")
            print(f"{GREEN}[+] Nmap results saved to {output_file}{WHITE}")
        else:
            print(f"{WHITE}[!] No open ports found.{WHITE}")

    else:
        print(f"{WHITE}[!] Invalid scan level provided.{WHITE}")
        return

def gobuster_scan(enum_level, target, wordlist, domain):

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    
    print(f"{CYAN}[*] GoBuster Scan for {target} starting...")
    if enum_level == 'light':
        output_file = f"gobuster_hidden_dir_{target.replace('.', '-')}_{timestamp}.txt"
        gobuster_hidden_dir_results = run_command(f"gobuster dir -u {target} -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t10 2>&1 | tee {output_file}")
        print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

        if domain:
            output_file = f"gobuster_vhost_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_vhost_results = run_command(f"gobuster vhost -u {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

            output_file = f"gobuster_subdomain_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_subdomain_results = run_command(f"gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -i --wildcard -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")
        
    elif enum_level == 'medium':
        output_file = f"gobuster_hidden_dir_{target.replace('.', '-')}_{timestamp}.txt"
        gobuster_hidden_dir_results = run_command(f"gobuster dir -u {target} -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t10 2>&1 | tee {output_file}")
        print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

        if domain:
            output_file = f"gobuster_vhost_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_vhost_results = run_command(f"gobuster vhost -u {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

            output_file = f"gobuster_subdomain_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_subdomain_results = run_command(f"gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -i --wildcard -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

    elif enum_level == 'heavy':
        output_file = f"gobuster_hidden_dir_{target.replace('.', '-')}_{timestamp}.txt"
        gobuster_hidden_dir_results = run_command(f"gobuster dir -u {target} -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t10 2>&1 | tee {output_file}")
        print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

        if domain:
            output_file = f"gobuster_vhost_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_vhost_results = run_command(f"gobuster vhost -u {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")

            output_file = f"gobuster_subdomain_{target.replace('.', '-')}_{timestamp}.txt"
            gobuster_subdomain_results = run_command(f"gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -i --wildcard -t10 2>&1 | tee {output_file}")
            print(f"{GREEN}[+] GoBuster results saved to {output_file}{WHITE}")
    else:
        print(f"{WHITE}[!] Invalid scan level provided.{WHITE}")
        return


def extract_ports(nmap_output):
    ports = []
    # Split the output into lines
    for line in nmap_output.splitlines():
        # Check if the line contains port no
        if '/tcp' in line: #i see so many things going wrong here if its UDP but meh
            # extract port no from line
            port = line.split('/')[0].strip()
            ports.append(port)
    
    return ports

# def dirbuster_scan(target, wordlist):
#     print(f"\n=== DirBuster Scan for {target} using {wordlist} ===")
#     dirbuster_result = run_command(f"dirb http://{target}/ {wordlist} -o dirbuster_result.txt")
#     print(dirbuster_result)

def get_input():
    print(f"""
{WHITE}Usage: {GREEN}python LazyEnum.py [light/medium/heavy] -H 127.0.0.1 -w /usr/share/wordlists/rockyou.txt
{CYAN}FLAGS:

    -debug  For debugging purposes, prints out more logs
    -D      domain
    -H      Host/IPAddress (required)
    -w      wordlist path (required)

{WHITE}Eg. python LazyEnum.py medium -H 127.0.0.1 -w /usr/share/wordlists/rockyou.txt -debug
""")

    enum_level = sys.argv[1]
    if enum_level not in ["light", "medium", "heavy"]:
        print(f"{WHITE}[!] Invalid load level. Choose from [light/medium/heavy]{WHITE}")
        sys.exit(1)

    target = None
    wordlist = None
    domain = None
    flags = []

    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-H' and i + 1 < len(sys.argv):
            target = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-w' and i + 1 < len(sys.argv):
            wordlist = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-D' and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-debug':
            flags.append(sys.argv[i])
            i += 1
        else:
            print(f"{WHITE}[!] Unrecognized option: {sys.argv[i]}{WHITE}")
            sys.exit(1)

    # Ensure mandatory flags are present
    if not target:
        print(f"{WHITE}[!] Missing required flags -H {WHITE}")
        sys.exit(1)

    # Default wordlist if not provided
    wordlist = wordlist if wordlist else "/usr/share/wordlists/dirb/common.txt"
    
    debug_mode = "-debug" in flags

    return enum_level, target, wordlist, domain, flags, debug_mode

# def enum():
#     target, wordlist = get_input()
#     nmap_scan(target)
#     dirbuster_scan(target, wordlist)

def check_installed_modules(debug_mode):
    #checking for nmap
    nmap_check = 'dpkg -l | grep "nmap"'

    if run_command(nmap_check) is not None:
        print(f"{GREEN}[+] Nmap is Installed. ")
    else:
        nmap_install()

    #check for etc.
    gobuster_check = 'dpkg -l | grep "dirb"'

    if run_command(gobuster_check) is not None:
        print(f"{GREEN}[+] Gobuster is Installed. ")
    else:
        gobuster_install()

        

def nmap_install():
    print(f"{YELLOW}[!] Nmap is not Installed. Install Nmap? (Y/N)")
    try:
        user_input = input(f"{YELLOW}Install Nmap? (Y/N)")
        if str(user_input) == 'Y' or str(user_input) == 'y':
            print(f"{GREEN}[*] Installing Nmap...{YELLOW}")
            print(run_command("sudo apt install nmap"))

        else:
            print(f"{YELLOW}[!] Exiting...")
    except:
        print(f"{YELLOW}[!] Exiting...")

def gobuster_install():
    print(f"{YELLOW}[!] GoBuster is not Installed. Install GoBuster? (Y/N)")
    try:
        user_input = input(f"{YELLOW}Install GoBuster? (Y/N)")
        if str(user_input) == 'Y' or str(user_input) == 'y':
            print(f"{GREEN}[*] Installing GoBuster...{YELLOW}")
            print(run_command("sudo apt install gobuster"))

        else:
            print(f"{YELLOW}[!] Exiting...")
    except:
        print(f"{YELLOW}[!] Exiting...")

def print_logo():
    banner = f"""{MAGENTA}
#########################################################################
#                                                                       #
#   _                    _____                               _   ___    #
#  | |    __ _ _____   _| ____|_ __  _   _ _ __ ___   __   _/ | / _ \   #
#  | |   / _` |_  / | | |  _| | '_ \| | | | '_ ` _ \  \ \ / / || | | |  #
#  | |__| (_| |/ /| |_| | |___| | | | |_| | | | | | |  \ V /| || |_| |  #
#  |_____\__,_/___|\__, |_____|_| |_|\__,_|_| |_| |_|   \_/ |_(_)___/   #
#                  |___/                                                #
#                                                                       #
#########################################################################

            LazyEnum built by lazy people for Lazy people
"""
    print(banner)

def show_options(enum_level, target, wordlist, domain, flags, debug_mode):
    if debug_mode == True:
        print(f"{YELLOW}**DEBUG MODE ENABLED**\n")
        print(f"{WHITE}Script Options\n________________________________\n")
        print(f"{WHITE}Scan Level : {GREEN}{enum_level}\n{WHITE}Target IP: {GREEN}{target}\n{WHITE}Target domain: {GREEN}{domain}\n{WHITE}Wordlist: {GREEN}{wordlist}\n{WHITE}Flags: {GREEN}{flags}\n{WHITE}Debug: {GREEN}{debug_mode}")
        print(f"{WHITE}________________________________\n")
    else:
        print(f"{WHITE}Options\n________________________________\n")
        print(f"{WHITE}Scan Level : {GREEN}{enum_level}\n{WHITE}Target: {GREEN}{target}\n{WHITE}Wordlist: {GREEN}{wordlist}")
        print(f"{WHITE}________________________________\n")

def enum(enum_level, target, wordlist, domain, flags, debug_mode):
    print(f"{CYAN}[*] Enumeration Scan for {target} starting...")
    # create seperate threads
    nmap_thread = threading.Thread(target=nmap_scan, args=(enum_level, target))
    gobuster_thread = threading.Thread(target=gobuster_scan, args=(enum_level, target, wordlist, domain))

    # Start both threads
    nmap_thread.start()
    gobuster_thread.start()

    # Wait for both threads to finish
    nmap_thread.join()
    gobuster_thread.join()
    print(f"{MAGENTA}Enumeration Scans Complete!")

def main():
    print_logo()
    enum_level, target, wordlist, domain, flags, debug_mode = get_input()
    show_options(enum_level, target, wordlist, domain, flags, debug_mode)

    check_installed_modules(debug_mode)

    enum(enum_level, target, wordlist, domain, flags, debug_mode)

    
if __name__ == "__main__":
    main()