 
import requests

url = ' Your File Path '
r = requests.get(url, allow_redirects=True)
open('THMlogo.png', 'wb').write(r.content)
