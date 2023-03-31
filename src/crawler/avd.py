import urllib.parse

import httpx

from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
from bs4 import BeautifulSoup


class AVDCrawler(BaseCrawler):
    name_ch = "阿里云漏洞库"
    name_en = "aliyun-avd"
    home_page = "https://avd.aliyun.com/high-risk/list"
    url = "https://avd.aliyun.com/high-risk/list"

    def __init__(self):
        super().__init__()

    def get_cves(self):
        response = httpx.get(self.url, headers=self.headers, timeout=self.timeout)
        cves = []
        if response.status_code != 200:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
            return cves
        soup = BeautifulSoup(response.text, "lxml")
        trs = soup.select("table > tbody > tr")
        for tr in trs:
            tds = tr.select("td")
            if len(tds) != 5:
                continue
            cve = CVEInfo()
            cve.id = tds[0].text.strip()
            cve.src = urllib.parse.urljoin(self.url, tds[0].find("a").get("href"))
            cve.url = urllib.parse.urljoin(self.url, tds[0].find("a").get("href"))
            cve.time = tds[3].text.strip()
            cve.title = tds[1].text.strip()
            infos = []
            for button in tds[4].select("button"):
                title = button.get("title", "").strip()
                if title:
                    infos.append(title)
            cve.info = ", ".join(infos)
            cves.append(cve)
        return cves


if __name__ == "__main__":
    print(AVDCrawler().get_cves())
