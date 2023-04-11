from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
import httpx
import re


class RedQueen(BaseCrawler):
    name_ch = "红后"
    name_en = "RedQueen"
    home_page = "https://redqueen.tj-un.com/IntelHome.html"
    url_list = "https://redqueen.tj-un.com/Json/intelHomeVulnIntelList.json"
    url_cve = "https://redqueen.tj-un.com/IntelDetails.html?id="

    def get_cves(self, limit=10):
        data = 'query={ "page": 1, "page_count": %d }' % limit

        response = httpx.post(
            self.url_list,
            headers={
                **self.headers,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            },
            content=data,
            timeout=self.timeout,
        )

        cves = []
        if response.status_code == 200:
            for obj in response.json().get("intgs"):
                cve = self.to_cve(obj)
                if cve.is_vaild():
                    cves.append(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        response = httpx.get(
            "https://redqueen.tj-un.com/Json/intelHomeKeyList.json",
            headers=self.headers,
            timeout=self.timeout,
        )
        if response.status_code == 200:
            for obj in response.json().get("intel_list", []):
                cve = CVEInfo()
                cve.src = self.name_ch
                cve.url = self.url_cve + obj["id"]
                cve.time = obj["pub_time"]
                cve.title = obj["title"]
                cve.id = obj["id"]
                cve.info = obj["source"]
                cves.append(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        response = httpx.get(
            "https://redqueen.tj-un.com/Json/intelHomeNewInfo.json",
            headers=self.headers,
            timeout=self.timeout,
        )
        if response.status_code == 200:
            for obj in response.json().get("new_info", []):
                cve = CVEInfo()
                cve.src = self.name_ch
                cve.url = "https://redqueen.tj-un.com/InfoDetails.html?id=" + obj["id"]
                cve.time = obj["pub_time"]
                cve.title = obj["title"]
                cve.id = obj["id"]
                cves.append(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        return cves

    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.name_ch
        cve.url = self.url_cve + json_obj["id"]
        cve.time = json_obj["pub_time"]

        title = json_obj.get("title")
        cve.title = re.sub(r"CVE-\d+-\d+", "", title).strip()

        rst = re.findall(r"(CVE-\d+-\d+)", title)
        cve.id = rst[0] if rst else ""
        return cve


if __name__ == "__main__":
    print(RedQueen().cves())
