# xsscrawler.py

import requests
from xssLog import *
from xsshelper import *
from xsscore import *
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from multiprocessing import Process

class crawler:
    visited = []

    @classmethod
    def get_links(cls, base, proxy, headers, cookie):
        """
        Get links from a given base URL
        """
        links = []
        conn = session(proxy, headers, cookie)
        text = conn.get(base).text
        soup = BeautifulSoup(text, "html.parser")

        for obj in soup.find_all("a", href=True):
            url = obj["href"]

            if url.startswith(("http://", "https://")):
                continue
            elif url.startswith(("mailto:", "javascript:", "about:", "tel:")):
                continue
            elif urljoin(base, url) in cls.visited:
                continue
            else:
                links.append(urljoin(base, url))
                cls.visited.append(urljoin(base, url))

        return links

    @classmethod
    def crawl(cls, base, depth, proxy, headers, level, method, cookie):
        """
        Crawl a website starting from the base URL
        """
        urls = cls.get_links(base, proxy, headers, cookie)

        for url in urls:
            p = Process(target=core.main, args=(url, proxy, headers, level, cookie, method))
            p.start()
            p.join()

            if depth != 0:
                cls.crawl(url, depth - 1, proxy, headers, level, method, cookie)
            else:
                break
