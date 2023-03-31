from src.bean.cve_info import CVEInfo
import httpx
import re
from lxml import etree
from datetime import datetime

from src.crawler.base import BaseCrawler
from src.utils import log


class Tenable(BaseCrawler):
    name_ch = "Tenable (Nessus)"
    name_en = "Tenable (Nessus)"
    home_page = "https://www.tenable.com/"
    url = "https://www.tenable.com/cve/feeds?sort=newest"

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=10):
        response = httpx.get(self.url, headers=self.headers, timeout=self.timeout)

        cves = []
        if response.status_code == 200:
            data = "".join(response.text.split("\n")[1:])
            rss = etree.XML(data)
            items = rss.xpath("//item")

            cnt = 0
            for item in items:
                cve = self.to_cve(item)
                if cve.is_vaild():
                    if cnt < limit:
                        cves.append(cve)
                        # log.debug(cve)
                        cnt += 1
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]"
                % (self.NAME_CH(), response.status_code)
            )
        return cves

    def to_cve(self, item):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.id = item.xpath("./title")[0].text
        cve.url = item.xpath("./link")[0].text

        _time = item.xpath("./pubDate")[0].text
        cve.time = datetime.strptime(_time, "%a, %d %b %Y %H:%M:%S GMT")

        _desc = item.xpath("./description")[0].text
        _desc = _desc.replace("\r", "").replace("\n", "")
        cve.info = re.findall(r"Description</h3>\s*<p>(.*?)</p>", _desc, re.DOTALL)[
            0
        ].strip()
        cve.title = cve.info
        return cve
