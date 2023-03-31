from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
import httpx


class QiAnXin(BaseCrawler):
    name_ch = "奇安信"
    name_en = "QiAnXin"
    home_page = "https://ti.qianxin.com/vulnerability"
    url = "https://ti.qianxin.com/alpha-api/v2/nox/api/web/portal/key_vuln/list"

    def get_cves(self):
        response = httpx.post(
            self.url,
            json={"page_no": 1, "page_size": 10, "vuln_keyword": ""},
            headers=self.headers,
            timeout=self.timeout,
        )
        json_data = response.json()
        cves = []
        if response.status_code == 200:
            for item in json_data["data"]["data"]:
                cve = CVEInfo()
                cve.id = item["cve_code"]
                cve.src = "qianxin_ti"
                cve.url = f"https://ti.qianxin.com/vul/{item['id']}"
                cve.time = item["publish_time"]
                cve.title = item["vuln_name"]
                cve.info = item["description"]
                cves.append(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        return cves



if __name__ == "__main__":
    print(QiAnXin().get_cves())
