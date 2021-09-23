import sys
from src import config
from src.utils import log
from src.utils.sqlite import SqliteSDBC

from src.crawler.cert360 import Cert360
from src.crawler.nsfocus import NsFocus
from src.crawler.qianxin import QiAnXin
from src.crawler.anquanke import AnQuanKe
from src.crawler.vas import Vas

import src.notice.page as page
import src.notice.mail as mail
import src.utils.git as git


def help_info():
    return """
    -h                帮助信息
    -top <number>     播报时每个来源最多取最新的前 N 个 CVE（默认 10）
    -ac               自动提交变更到仓库（可自动归档、生成 Github Page，默认关闭）
    -mg               使用 Github workflows Actions 发送邮件（默认关闭）
    -ms  <mail-smtp>  用于发送播报信息的邮箱 SMTP 服务器（默认 smtp.126.com）
    -mu  <mail-user>  用于发送播报信息的邮箱账号（默认 ThreatBroadcast@126.com）
    -mp  <mail-pass>  用于发送播报信息的邮箱密码（部分邮箱为授权码）
    -qu  <qq-user>    用于向 QQ 群发送播报信息的 QQ 账号
    -qp  <qq-pass>    用于发送播报信息的 QQ 密码
"""


def init():
    log.init()

    sdbc = SqliteSDBC(config.DB_PATH)
    sdbc.init(config.SQL_PATH)


def main(
    help,
    top,
    auto_commit,
    mail_by_github,
    mail_smtp,
    mail_user,
    mail_pass,
):
    if help:
        log.info(help_info())

    else:
        all_cves = {}
        srcs = [Cert360(), NsFocus(), QiAnXin(), AnQuanKe(), Vas()]
        for src in srcs:
            cve_list = src.cves()
            if cve_list:
                to_log(cve_list)
                all_cves[src] = cve_list

        if all_cves:
            page.to_page(top)
            mail.to_mail(mail_by_github, all_cves, mail_smtp, mail_user, mail_pass)

            if auto_commit:
                git.auto_commit()


def to_log(cves):
    map(lambda cve: log.info(cve.to_msg()), cves)


def get_sys_args(sys_args):
    help = False
    top = 10
    auto_commit = False
    mail_by_github = False
    mail_smtp = "smtp.qq.com"
    mail_user = "threatbroadcast@qq.com"
    mail_pass = ""

    idx = 1
    size = len(sys_args)
    while idx < size:
        try:
            if sys_args[idx] == "-h":
                help = True

            elif sys_args[idx] == "-top":
                idx += 1
                top = int(sys_args[idx])

            elif sys_args[idx] == "-ac":
                auto_commit = True

            elif sys_args[idx] == "-mg":
                mail_by_github = True

            elif sys_args[idx] == "-ms":
                idx += 1
                mail_smtp = sys_args[idx]

            elif sys_args[idx] == "-mu":
                idx += 1
                mail_user = sys_args[idx]

            elif sys_args[idx] == "-mp":
                idx += 1
                mail_pass = sys_args[idx]

        except:
            pass
        idx += 1
    return (
        help,
        top,
        auto_commit,
        mail_by_github,
        mail_smtp,
        mail_user,
        mail_pass,
    )


if __name__ == "__main__":
    init()
    main(*get_sys_args(sys.argv))
