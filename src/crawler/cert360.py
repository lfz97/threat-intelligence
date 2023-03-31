from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
import httpx
import json
import re
import time


class Cert360(BaseCrawler):
    name_ch = "360"
    name_en = "360"
    home_page = "https://cert.360.cn/warning"
    url_list = "https://cert.360.cn/warning/searchbypage"
    url_cve = "https://cert.360.cn/warning/detail?id="

    def get_cves(self, limit=6):
        params = {"length": limit, "start": 0}

        response = httpx.get(
            self.url_list, headers=self.headers, params=params, timeout=self.timeout
        )

        cves = []
        if response.status_code == 200:
            json_obj = json.loads(response.text)
            for obj in json_obj.get("data"):
                cve = self.to_cve(obj)
                if cve.is_vaild():
                    cves.append(cve)
                    # log.debug(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        return cves

    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.name_ch
        cve.url = self.url_cve + (json_obj.get("id") or "")
        cve.info = (json_obj.get("description") or "").strip().replace("\n\n", "\n")

        seconds = json_obj.get("update_time") or 0
        localtime = time.localtime(seconds)
        cve.time = time.strftime("%Y-%m-%d %H:%M:%S", localtime)

        title = json_obj.get("title") or ""
        cve.title = re.sub(r"CVE-\d+-\d+:", "", title).strip()

        rst = re.findall(r"(CVE-\d+-\d+)", title)
        cve.id = rst[0] if rst else ""
        return cve


if __name__ == "__main__":
    c = Cert360()
    cves = c.get_cves()
    for cve in cves:
        print(cve)
