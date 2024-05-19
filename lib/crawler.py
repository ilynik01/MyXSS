from threading import Thread
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests.exceptions import TooManyRedirects

from lib.log import *
from lib.mysession import MySession
from lib.scanner import *


class crawler:
    crawling_list=[]
    
    @classmethod
    def crawlLinks(self, base):
        url_links = []
        session = MySession()

        try:
            content = session.get(base).text
            page = BeautifulSoup(content, "html.parser")

            for tag in page.find_all("a", href=True):
                link = urljoin(base, tag["href"])

                if self.skip_url(link, base):
                    continue

                self.crawling_list.append(link)
                url_links.append(link)
        except TooManyRedirects:
            Log.error(f"Crawler. Too many redirects while trying to access: {base}")

        return url_links

    @staticmethod
    def skip_url(link, base):
        return (
            link in crawler.crawling_list or
            link.startswith("mailto:") or
            link.startswith("javascript:") or
            not (link.startswith(base) or "://" not in link)
        )

    @classmethod
    def crawl(self,base,files,depth=3,callback=None):

        print("depth: ", depth)

        links = self.crawlLinks(base)
        threads = []

        for link in links:
            if link.startswith("https://") or link.startswith("http://"):
                t = Thread(target=scanner.main, args=(link, files))
                t.start()
                threads.append(t)
                if depth > 0:
                    t_crawl = Thread(target=self.crawl, args=(link, files, depth-1))
                    t_crawl.start()
                    threads.append(t_crawl)

        for t in threads:
            t.join()

        if callback is not None:
            callback()



