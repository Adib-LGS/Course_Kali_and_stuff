"""Once subdomains have been discovered, the next step would be to find directories.

The following code will build a simple directory enumeration tool."""

import requests 
import sys 

#sub_list = open("your own wordlist.txt").read() 
#directories = sub_list.splitlines()

wordlist_location = str(input('Enter wordlist file location: '))

with open(wordlist_location, 'r') as file:
    for line in file.readlines():
        directories = sub_list.splitlines()

        for dir in directories:
            dir_enum = f"http://{sys.argv[1]}/{dir}.html" 
            r = requests.get(dir_enum)
            if r.status_code==404: 
                pass
            else:
                print("Valid directory:" ,dir_enum)
