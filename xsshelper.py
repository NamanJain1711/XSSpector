# xsshelper.py

import requests

# Colors
RESETEND = '\033[0m'
WHITE = '\033[1;37m'
BLUE = '\033[1;34m'
MAGENTA = '\033[1;35m'
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[1;36m'

# Styling
underline = "\033[4m"

def session(proxies, headers, cookie):
    if cookie:
        try:
            cookie_dict = dict(x.split("=") for x in cookie.replace(";", "&").split("&"))
        except Exception as e:
            print("Invalid cookie format. Please ensure it's a valid key-value pair string.")
            exit()
    else:
        cookie_dict = {}
    r = requests.Session()
    r.proxies = proxies
    r.headers = headers
    r.cookies.update(cookie_dict)
    return r

logo = GREEN + """
************************************************************
█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█
█                       » XSSpector «                      █
█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
************************************************************
"""

print(logo)
