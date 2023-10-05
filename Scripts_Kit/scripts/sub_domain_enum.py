"""Finding subdomains used by the target organization is an effective way to increase the attack surface and discover more vulnerabilities.
#####The script will use a list of potential subdomains and prepends them to the domain name provided via a command-line argument.
The script then tries to connect to the subdomains and assumes the ones that accept the connection exist"""

import requests 
import sys 

sub_list = open("your own subdomains.txt file").read() 
subdoms = sub_list.splitlines()

for sub in subdoms:
    sub_domains = f"http://{sub}.{sys.argv[1]}" 

    try:
        requests.get(sub_domains)
    
    except requests.ConnectionError: 
        pass
    
    else:
        print("Valid domain: ",sub_domains)  