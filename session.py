#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @Author  :   Arthals
# @File    :   session.py
# @Time    :   2025/01/25 01:44:46
# @Contact :   zhuozhiyongde@126.com
# @Software:   Visual Studio Code


import base64
import json
import os
import random
import time
from typing import Dict, Iterable, List
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
GRADE_INDEX_URL = "https://apps.bjmu.edu.cn/jwapp/sys/cjcx/*default/index.do"
GRADE_QUERY_URL = "https://apps.bjmu.edu.cn/jwapp/sys/cjcx/modules/cjcx/xscjcx.do"


class Session(requests.Session):
    def __init__(self, config, notifier=None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._config = config
        self._notifier = notifier
        self.verify = False  # PKUHSC 证书链经常异常，关闭校验更稳
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        self._grade_referer = None
        self.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Connection": "keep-alive",
            }
        )

    def __del__(self):
        self.close()

    def get(self, url, *args, **kwargs):
        res = super().get(url, *args, **kwargs)
        res.raise_for_status()
        return res

    def post(self, url, *args, **kwargs):
        res = super().post(url, *args, **kwargs)
        res.raise_for_status()
        return res

    def login(self) -> bool:
        """登录北医医学部统一身份认证"""
        login_url = self._build_login_url()
        login_page = self.get(login_url)
        soup = BeautifulSoup(login_page.text, "html.parser")

        lt = soup.find("input", {"name": "lt"})
        execution = soup.find("input", {"name": "execution"})
        salt = soup.find("input", {"id": "pwdEncryptSalt"})
        if not all([lt, execution, salt]):
            raise ValueError("登录页缺少必要字段，无法继续登录")

        encrypted_pwd = self._encrypt_password(self._config["password"], salt["value"])

        form_data = {
            "username": self._config["username"],
            "password": encrypted_pwd,
            "captcha": "",
            "_eventId": "submit",
            "cllt": "userNameLogin",
            "dllt": "generalLogin",
            "lt": lt["value"],
            "execution": execution["value"],
            "rmShown": "1",
        }

        # 发送登录请求并跟随重定向直到进入成绩系统
        login_headers = dict(self.headers)
        login_headers.update(
            {
                "Referer": login_page.url,
                "Origin": "https://auth.bjmu.edu.cn",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

        response = self.post(
            login_page.url,
            data=form_data,
            allow_redirects=True,
            headers=login_headers,
        )
        if "统一身份认证平台" in response.text:
            raise ValueError("统一身份认证失败，请检查账号或密码")

        # 登录成功后记录成绩页面，用于后续成绩查询 Referer
        self._grade_referer = response.url or GRADE_INDEX_URL
        self.headers["Referer"] = self._grade_referer
        return True

    def _build_login_url(self) -> str:
        timestamp = int(time.time() * 1000)
        service = (
            f"{GRADE_INDEX_URL}"
            f"?t_s={timestamp}&amp_sec_version_=1&gid_={self._config['gid']}"
            "&EMAP_LANG=zh&THEME=bjmu#/cjcx"
        )
        encoded_service = quote(service, safe="")
        return f"https://auth.bjmu.edu.cn/authserver/login?service={encoded_service}"

    def get_grade(self):
        """获取成绩"""
        payload = {
            "querySetting": json.dumps(
                [
                    {
                        "name": "SFYX",
                        "caption": "是否有效",
                        "linkOpt": "AND",
                        "builderList": "cbl_m_List",
                        "builder": "m_value_equal",
                        "value": "1",
                        "value_display": "是",
                    },
                    {
                        "name": "SHOWMAXCJ",
                        "caption": "显示最高成绩",
                        "linkOpt": "AND",
                        "builderList": "cbl_m_List",
                        "builder": "m_value_equal",
                        "value": 0,
                        "value_display": "否",
                    },
                ],
                ensure_ascii=False,
            ),
            "*order": "-XNXQDM,-KCH,-KXH",
            "pageSize": 999,
            "pageNumber": 1,
        }

        headers = {
            "Origin": "https://apps.bjmu.edu.cn",
            "Referer": self._grade_referer or GRADE_INDEX_URL,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.post(GRADE_QUERY_URL, data=payload, headers=headers).json()
        if res.get("code") not in ("0", 0):
            raise ValueError(f"获取成绩失败: {res}")

        with open("current.json", "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=4)
        return res

    def check_init(self):
        """检查是否已经初始化历史成绩数据"""
        if os.path.exists("data.json"):
            return

        with open("current.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        with open("data.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        if self._notifier:
            self._notifier.send(
                title="[成绩更新] 初始化",
                info="成功初始化医学部成绩数据",
            )

    def check_update(self):
        """检查成绩更新并返回新增课程信息"""
        try:
            self.check_init()

            with open("current.json", "r", encoding="utf-8") as f:
                new_data = json.load(f)

            with open("data.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)

            old_courses = {item["id"] for item in self._flatten_courses(old_data)}
            new_courses_detail = self._flatten_courses(new_data)

            new_courses = [
                course
                for course in new_courses_detail
                if course["id"] and course["id"] not in old_courses
            ]

            with open("data.json", "w", encoding="utf-8") as f:
                json.dump(new_data, f, ensure_ascii=False, indent=4)

            print(f"{'[Succeed]':<15}: 成功发现 {len(new_courses)} 门新课程")

            if new_courses and self._notifier:
                for course in new_courses:
                    self._notifier.send(
                        title=f"[成绩更新] {course['name']}",
                        info=f"成绩：{course['grade']}，绩点：{course['gpa']}，学分：{course['credit']}",
                    )

            return new_courses

        except Exception as e:
            print(f"检查更新时出错: {e}")
            return []

    def _encrypt_password(self, password: str, salt: str) -> str:
        random_prefix = "".join(random.choices(AES_CHARS, k=64))
        iv = "".join(random.choices(AES_CHARS, k=16))

        payload = (random_prefix + password).encode("utf-8")
        cipher = AES.new(salt.encode("utf-8")[:16], AES.MODE_CBC, iv.encode("utf-8"))

        encrypted_bytes = cipher.encrypt(pad(payload, AES.block_size, style="pkcs7"))
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def _flatten_courses(self, data: Dict) -> List[Dict[str, str]]:
        rows = list(self._iter_rows(data))
        courses = []
        for row in rows:
            cid = (
                row.get("WID")
                or row.get("bkcjbh")
                or "-".join(
                    filter(
                        None,
                        [
                            row.get("XNXQDM") or row.get("xnxq"),
                            row.get("KCH") or row.get("kch"),
                            row.get("KXH") or row.get("kxh"),
                        ],
                    )
                )
            )
            if not cid:
                continue

            if row.get("DJCJLXDM_DISPLAY") == "两级制":
                grade = row.get("DJCJMC")
            else:
                grade = row.get("ZCJ") or row.get("xqcj") or "无"
            courses.append(
                {
                    "id": cid,
                    "name": row.get("XSKCM") or row.get("kcmc") or "无",
                    "grade": grade,
                    "gpa": row.get("XFJD") or row.get("jd") or row.get("gpa") or "无",
                    "credit": row.get("XF") or row.get("xf") or "无",
                }
            )
        return courses

    def _iter_rows(self, data: Dict) -> Iterable[Dict]:
        if not isinstance(data, dict):
            return []

        datas_section = data.get("datas")
        if isinstance(datas_section, dict):
            xscjcx = datas_section.get("xscjcx", {})
            rows = xscjcx.get("rows")
            if isinstance(rows, list):
                return rows

        # 兼容旧版北大成绩结构
        rows = []
        for term in data.get("cjxx", []):
            if not isinstance(term, dict):
                continue
            courses = term.get("list", [])
            if isinstance(courses, list):
                rows.extend(courses)
        return rows


class BarkNotifier:
    def __init__(self, token):
        self._token = token

    def send(self, title, info):
        requests.post(
            f"https://api.day.app/{self._token}",
            data={
                "title": title,
                "body": info,
                "icon": "https://cdn.arthals.ink/pku.jpg",
                "level": "timeSensitive",
            },
        )
