# xsspector.py

import signal
import sys
import argparse
from xsshelper import *
from xssLog import *
from xsscore import *
from xsscrawler import *
from random import randint
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Constants
epilog = WHITE + """
    Example usage:
    xsshunter.py -u <target> [options]
"""

agent = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Signal handler
def signal_handler(sig, frame):
    """Perform cleanup actions here"""
    # Close any open file handles or network connections
    # Terminate any unfinished tasks or threads
    # Release any system resources
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Helper functions
def check(getopt):
    """Check payload level and return payload"""
    payload = int(getopt.payload_level)
    if payload < 1 and getopt.payload is None:
        Log.info("Do you want use custom payload (Y/n)?")
        answer = input("> " + WHITE)
        if answer.lower().strip() == "y":
            Log.info("Write the XSS payload below")
            payload = input("> " + WHITE)
        else:
            payload = core.generate(randint(1))
    else:
        payload = core.generate(payload)
    return payload if getopt.payload is None else getopt.payload

def read_payloads_from_file(filename):
    """Read payloads from a file"""
    try:
        with open(filename, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]
        return payloads
    except FileNotFoundError:
        Log.error(f"File '{filename}' not found.")
        return []

# Main function
def start():
    # Parse arguments
    parse = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        usage=CYAN + "xsshunter.py -u <target> [options]",
        add_help=False
    )

    pos_opt = parse.add_argument_group("Options")
    pos_opt.add_argument("--help", action="store_true", default=False, help="Show usage and help parameters")
    pos_opt.add_argument("-u", metavar="", help="Target url (e.g. http://testphp.vulnweb.com)")
    pos_opt.add_argument("--depth", metavar="", help="Depth web page to crawl. Default: 2", default=2)
    pos_opt.add_argument("--payload-level", metavar="", help="Level for payload Generator, 1 for custom payload.  Default: 0", default=1)
    pos_opt.add_argument("--payload", metavar="", help="Load custom payload directly (e.g. <script>alert('Vigrahak')</script>)", default=None)
    pos_opt.add_argument("--payloads-file", metavar="", help="Load payloads from a file (e.g. payloads.txt)", default=None)
    pos_opt.add_argument("--method", metavar="", help="Method setting(s): \n\t0: GET\n\t1: POST\n\t2: GET and POST (default)", default=2, type=int)
    pos_opt.add_argument("--user-agent", metavar="", help="Request user agent (e.g. Chrome/2.1.1/...)", default=agent)
    pos_opt.add_argument("--single", metavar="", help="Single scan. No crawling just one address")
    pos_opt.add_argument("--proxy", default=None, metavar="", help="Set proxy (e.g. {'https':'https://10.10.1.10:1080'})")
    pos_opt.add_argument("--about", action="store_true", help="Print information about XSS tool")
    pos_opt.add_argument("--cookie", help="Set cookie (e.g {'ID=session')", default="ID=session", metavar="")
    pos_opt.add_argument("--fuzz", metavar="", help="Fuzz parameter URL (e.g. http://example.com/test?param=fuzz)")

    getopt = parse.parse_args()

    # Fuzz parameter URL
    if getopt.fuzz:
        original_url = urlparse(getopt.fuzz)
        query_string = parse_qs(original_url.query)

        for param, value in query_string.items():
            if getopt.payloads_file:
                payloads = read_payloads_from_file(getopt.payloads_file)
                for payload in payloads:
                    fuzz_url_with_payload = list(original_url)
                    query_string[param] = payload
                    fuzz_url_with_payload[4] = urlencode(query_string, doseq=True)
                    fuzz_url_with_payload = urlunparse(fuzz_url_with_payload)
                    Log.info("Fuzzing URL: " + fuzz_url_with_payload + GREEN + "  --->  " + payload)
                    s = session(getopt.proxy, getopt.user_agent, getopt.cookie)
                    response = s.get(fuzz_url_with_payload, allow_redirects=False)

                    if payload in response.text:
                        Log.high("XSS payload triggered: " + fuzz_url_with_payload + CYAN + " (Status code: " + str(response.status_code) + ")")
                        cont = input("XSS payload triggered. Continue? (Y/n): ")
                        if cont.lower() != "y":
                            Log.info("Exiting...")
                            exit(0)
                    else:
                        Log.info("XSS payload not triggered: " + fuzz_url_with_payload + CYAN + " (Status code: " + str(response.status_code) + ")")

                    # Reset query string
                    query_string[param] = value
            else:
                payload = check(getopt)
                fuzz_url_with_payload = list(original_url)
                query_string[param] = payload
                fuzz_url_with_payload[4] = urlencode(query_string, doseq=True)
                fuzz_url_with_payload = urlunparse(fuzz_url_with_payload)
                Log.info("Fuzzing URL: " + fuzz_url_with_payload + GREEN + "  --->  " + payload)
                s = session(getopt.proxy, getopt.user_agent, getopt.cookie)
                response = s.get(fuzz_url_with_payload, allow_redirects=False)

                if payload in response.text:
                    Log.high("XSS payload triggered: " + fuzz_url_with_payload + CYAN + " (Status code: " + str(response.status_code) + ")")
                    cont = input("XSS payload triggered. Continue? (Y/n): ")
                    if cont.lower() != "y":
                        Log.info("Exiting...")
                        exit(0)
                else:
                    Log.info("XSS payload not triggered: " + fuzz_url_with_payload + CYAN + " (Status code: " + str(response.status_code) + ")")

                # Reset query string
                query_string[param] = value

    # Scan target URL
    elif getopt.u:
        if getopt.payloads_file:
            payloads = read_payloads_from_file(getopt.payloads_file)
            for payload in payloads:
                core.main(getopt.u, getopt.proxy, getopt.user_agent, payload, getopt.cookie, getopt.method)
        else:
            core.main(getopt.u, getopt.proxy, getopt.user_agent, check(getopt), getopt.cookie, getopt.method)
        crawler.crawl(getopt.u, int(getopt.depth), getopt.proxy, getopt.user_agent, check(getopt), getopt.method, getopt.cookie)

    # Single scan
    elif getopt.single:
        if getopt.payloads_file:
            payloads = read_payloads_from_file(getopt.payloads_file)
            for payload in payloads:
                core.main(getopt.single, getopt.proxy, getopt.user_agent, payload, getopt.cookie, getopt.method)
        else:
            core.main(getopt.single, getopt.proxy, getopt.user_agent, check(getopt), getopt.cookie, getopt.method)

    # Print information about XSS tool
    elif getopt.about:
        print(CYAN + """
                                             - By Vigrahak
Have a beer : https://www.paypal.com/paypalme/SourrahS1828
""" + epilog)

    # Print help
    else:
        parse.print_help()

if __name__ == "__main__":
    start()
