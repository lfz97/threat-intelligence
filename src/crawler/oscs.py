import httpx
import json
from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log


class OSCS(BaseCrawler):
    name_ch = "OSCS"
    name_en = "Open Source China Security"
    home_page = "https://www.oscs.org.cn/"
    url_list = "https://www.oscs1024.com/oscs/v1/intelligence/list"
    url_cve = "https://www.oscs.org.cn/oscs/cve/details/"

    def get_cves(self, limit=10):
        data = {"page": 1, "page_size": limit}

        response = httpx.post(
            self.url_list,
            headers={
                **self.headers,
                "Content-Type": "application/json; charset=UTF-8",
            },
            content=json.dumps(data),
            timeout=self.timeout,
        )

        cves = []
        if response.status_code == 200:
            for obj in response.json()["data"]["data"]:
                cve = self.to_cve(obj)
                cves.append(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        return cves

    def to_cve(self, item):
        cve = CVEInfo()
        cve.id = item["mps"]
        cve.src = self.name_ch
        cve.url = item["url"]
        cve.time = item["public_time"]
        cve.title = item["title"]
        cve.info = item["level"]
        return cve


if __name__ == "__main__":
    print(OSCS().cves())
