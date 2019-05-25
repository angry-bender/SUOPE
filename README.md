# SUOPE - SSH USER OR PASSWORD ENUMERATION by Samuel Freeman

     
                )     (    )                      SSH User or Password Enmeration  
                 )     )  ( 
                  )    )   (         ,adPPYba, 88       88  ,adPPYba,  8b,dPPYba,   ,adPPYba,  
               _.(--'('''--)._      I8[    "" 88       88 a8"     "8a 88P'    "8a a8P_____88      
              /, _..-----).._,\      `"Y8ba,  88       88 8b       d8 88       d8 8PP"
             |  `'''-----'''`  |    aa    ]8I "8a,   ,a88 "8a,   ,a8" 88b,   ,a8" "8b,   ,aa 
              \               /     `"YbbdP"'  `"YbbdP'Y8  `"YbbdP"'  88`YbbdP"'   `"Ybbd8"' 
               '.           .'                                        88               
                 '--.....--'                                          88 
                                                             V1.0.5
                                                ASCII Art Credit ascii.co.uk
                                                
## Description
Exploits CVE-2018-15473 and runs a fuzzing test from a list of passwords, like the rockyou database

## Requirements
1. Python 3
     - pip
          - paramiko==2.4.1
          - cryptography==2.4.2
          - colorama

A Vulnerable SSH Box (OpenSSH 7.6 or Below or Ubuntu 16.04 LTS (Xenial Xerus):(1:7.2p2-4) - https://people.canonical.com/~ubuntu-security/cve/2018/CVE-2018-15473.html

## Usage
`chmod +x suope.py`

`./suope.py -h for help`
```
usage: suope.py [-h] [--port PORT] (--username USERNAME | --userfile USERFILE)
                (--password PASSWORD | --passfile PASSFILE)
                hostname

positional arguments:
  hostname             The target hostname or ip address

optional arguments:
  -h, --help           show this help message and exit
  --port PORT          The target port (Default 22)
  --username USERNAME  A Single Usename to Enumerate
  --userfile USERFILE  The list of usernames (one per line) to enumerate
                       through
  --password PASSWORD  A Single Password to Enumerate
  --passfile PASSFILE  The list of passwords (one per line) to enumerate
                       through
```
### Example Use case with single username and password set
`./suope.py 192.168.56.3 --username user --passfile = /tmp/rockyou.txt`

## Credits
Initial Exploit Code -  Justin Gardner, Penetration Tester @ SynerComm AssureIT - Github: https://github.com/Rhynorater/CVE-2018-15473-Exploit  

Initial Password Code - Sergeant Sploit - https://null-byte.wonderhowto.com/how-to/sploit-make-ssh-brute-forcer-python-0161689/


## Licence
Copyright (c) 2019 Samuel Freeman - All Rights Reserved

Permission is not granted without the express prior written approval from the author, to any person obtaining a copy of this software and associated documentation files (the "Software"), to copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
