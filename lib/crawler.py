from threading import Thread
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests.exceptions import TooManyRedirects

from lib.log import *
from lib.mysession import MySession
from lib.scanner import *

class crawler:
    visited=[]
    
    @classmethod
    def getLinks(self,base):

        lst=[]
        conn=MySession()

        try:
            text=conn.get(base).text
            isi=BeautifulSoup(text,"html.parser")

            for obj in isi.find_all("a",href=True):
                url = urljoin(base, obj["href"])
                if url in self.visited:
                    continue
                elif url.startswith("mailto:") or url.startswith("javascript:"):
                    continue
                elif url.startswith(base) or "://" not in url:
                    self.visited.append(url)
                    lst.append(url)
        except TooManyRedirects:
            Log.warning("Crawler. Too many redirects while trying to access: " + base)
        return lst

    @classmethod
    def crawl(self,base,files,depth=3,callback=None):

        print("depth: ", depth)

        urls = self.getLinks(base)
        threads = []

        for url in urls:
            if url.startswith("https://") or url.startswith("http://"):
                t = Thread(target=scanner.main, args=(url, files))
                t.start()
                threads.append(t)
                if depth > 0:
                    t_crawl = Thread(target=self.crawl, args=(url, files, depth-1))
                    t_crawl.start()
                    threads.append(t_crawl)

        for t in threads:
            t.join()

        if callback is not None:
            callback()
            
	
