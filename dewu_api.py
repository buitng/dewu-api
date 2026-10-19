"""
得物蓝V自动发布工具 - 核心API模块
基于逆向分析得到的完整API调用逻辑
"""
import hashlib
import json
import os
import re
import time
import base64
import random
import uuid
import urllib.parse
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

try:  # heracles 解密仿真引擎（缺失不阻塞模块加载，仅在解密时报错）
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn import arm64_const as _uac
    _UNICORN_OK = True
except ImportError:
    _UNICORN_OK = False

from modules.rizhi import log

# ==================== HTTP 全量日志 ====================
# 所有出站请求经 http_call 发出，报文全量落盘 http_log.txt（远程排障用，写失败静默）
HTTP_LOG_FILE = Path(__file__).parent / "http_log.txt"


def _log_http_line(text: str) -> None:
    try:
        with open(HTTP_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
    except Exception:
        pass


def http_call(method: str, url: str, **kwargs) -> requests.Response:
    """统一出站请求封装：请求与响应全量写入 http_log.txt"""
    _log_http_line(f">>> {method.upper()} {url}")
    if kwargs.get("headers"):
        try:
            _log_http_line("    headers: "
                           + json.dumps(kwargs["headers"], ensure_ascii=False, default=str))
        except Exception:
            pass
    _data = kwargs.get("data")
    if _data is not None:
        if isinstance(_data, (bytes, bytearray)):
            _log_http_line(f"    body: <binary {len(_data)} bytes>")
        else:
            _log_http_line(f"    body: {_data}")
    if kwargs.get("json") is not None:
        try:
            _log_http_line("    json: "
                           + json.dumps(kwargs["json"], ensure_ascii=False, default=str))
        except Exception:
            pass
    response = requests.request(method, url, **kwargs)
    _log_http_line(f"<<< {response.status_code}")
    try:
        _log_http_line("    resp-headers: "
                       + json.dumps(dict(response.headers), ensure_ascii=False))
        # 全量落盘：发布等接口响应为 heracles 加密串（可达1万+字符），截断会解不开
        _log_http_line(f"    resp-body: {response.text}")
    except Exception:
        pass
    return response


# ==================== 抓包代理证书兼容 ====================
# Reqable 系统代理开启时，TLS 被其根证书重签，requests 默认不信任会导致 SSL 失败；
# 把 Reqable 根证书并入 certifi 信任库（REQUESTS_CA_BUNDLE），代理开关两种状态都能正常工作
def _setup_ca_bundle():
    reqable_ca = Path(r"C:\Users\Y\AppData\Roaming\Reqable\certificate\reqable-root.crt")
    if not reqable_ca.is_file():
        return
    try:
        import certifi
        bundle = Path(__file__).resolve().parent / "_ca_bundle.pem"
        certifi_pem = Path(certifi.where())
        need_rebuild = (not bundle.is_file()
                        or bundle.stat().st_mtime < max(reqable_ca.stat().st_mtime,
                                                        certifi_pem.stat().st_mtime))
        if need_rebuild:
            combined = certifi_pem.read_text(encoding="utf-8") + "\n" \
                + reqable_ca.read_text(encoding="utf-8")
            bundle.write_text(combined, encoding="utf-8")
        os.environ["REQUESTS_CA_BUNDLE"] = str(bundle)
    except Exception:
        pass


_setup_ca_bundle()

# ==================== 常量 ====================
DEWU_AES_HEX_KEY = b'mobile0123456789'
DEWU_AES_BASE64_KEY = b'd245a0ba8d678a61'
# ==================== 设备身份（静态 MIX 2S 真机指纹，2026-10-09 起设备静态化） ====================
# randomize_device 随机换设备机制已删除：发码已切白盒 data= 原样重放（真机抓包固化），
# 无需随机指纹绕 485 风控。本区与下方 LOGIN60_* 真机常量同源同值，现役消费者仅剩：
# 滑块兜底（_risk_stone_headers/risk_stone_call）、newSign uuid 回落、上传 object_key。
# 版本锚定 6.0（必须）：10001 实证 = 服务端版本门禁"请更新APP至最新版本"，5.6 已被拦截；
# 20006 实证 = 6.0 unionLogin 成功码（accessToken 在加密 data 内，heracles 解密提取）
DEFAULT_EDK = "6C7D61656D61352E6C7D7D7D616C353B3B6C3D3B6D386D3C693D3E3C6A6C3C2E6769616C356E6C3A3F393F6E3D393E386A3A3C396C"  # = LOGIN60_EDK
USER_AGENT = "duapp/6.0.0(android;10)"  # = LOGIN60_UA
FULL_UA = "Dalvik/2.1.0 (Linux; U; Android 10; MIX 2S MIUI/V12.5.1.0.QDGCNXM)/duapp/6.0.0(android;10)"  # = LOGIN60_WEBUA
DEVICE_BRAND = "Xiaomi"   # = LOGIN60_BRAND
DEVICE_TRAIT = "MIX 2S"   # webua 机型串空格形态（dudeviceTrait 头用 LOGIN60_TRAIT="MIX+2S"）
SHUMEII = "2026100904563362f7a65c484d2a8fd0ddb902fadd8b5d00a024190b795f4b"  # = LOGIN60_SHUMEIID
DEVICE_SK = "9UBtS5z3fsHiAWZCZzCpHFXxNDZFBH0jGe1JhHCRWZnMoa4ZTG0WORo63hprSuBYYWrufI38slrbNm0ELODhT6E2NN1s"  # = LOGIN60_SK
DEVICE_SKT = "adr1"
DEVICE_SKS = "0,adw2"
DEVICE_LTK = "00OHlxAZQWvrX5SfE2WqYusL4RZovcdbmC4NbahD4"  # = LOGIN60_LTK
DEVICE_ADI = "GcT7yA3LSqYiCtb622Wv-oDjFStoYIzd2Q9dJJ4W8Ac="  # = LOGIN60_ADI
DEVICE_SKC = "L672YizCTm9CfnY5wWE64"  # = LOGIN60_SKC
UUID_FIXED = "a668ae867143bb86"  # = LOGIN60_UUID（真机 uuid）
VERSION = "6.0.0"

# ==================== 6.0 登录链路真机指纹（LSPatch 真机抓包实证，2026-10-09） ====================
# Mix 2S 真机（Android 10 / MIUI 12.5.1，LSPatch+TrustMeAlready 改包抓包）：
# init→sendCaptcha→unionLogin 全链路 200 登录成功。全套身份取同一会话（shumeiid 尾 024190b795f4b），
# 发码/登录设备字段逐项一致——指纹撕裂假设真机实证成立。adi/ltk/skc 每请求动态漂移，
# 服务端不要求两接口一致：固定登录侧单值，同会话自洽。ltk/dhw 真机每请求变：
# ltk 固定登录侧样本值，dhw 每请求 secrets 随机（52hex，真机同构）。
LOGIN60_SHUMEIID = "2026100904563362f7a65c484d2a8fd0ddb902fadd8b5d00a024190b795f4b"
LOGIN60_ADI = "GcT7yA3LSqYiCtb622Wv-oDjFStoYIzd2Q9dJJ4W8Ac="
# stoken：数美下发，跨天稳定；init 用 44 短版（真机同会话 init 实抓）/ unionLogin 用 90 长版
LOGIN60_STOKEN_INIT = "AjJrIDwUn73RsJ_vQ-jogM2KcKdqhExbcnfT1WbyQWQr"
LOGIN60_STOKEN_LOGIN = "BQBqyAOCmGjxwATfetW2qbBzQmu25JAaTkkEJpZlTnTLshrQW82CRroQoGMpQm5EfpZZkH0I_rqN-bVQCdgDiM1WxQ"
LOGIN60_SK = "9UBtS5z3fsHiAWZCZzCpHFXxNDZFBH0jGe1JhHCRWZnMoa4ZTG0WORo63hprSuBYYWrufI38slrbNm0ELODhT6E2NN1s"
LOGIN60_EDK = "6C7D61656D61352E6C7D7D7D616C353B3B6C3D3B6D386D3C693D3E3C6A6C3C2E6769616C356E6C3A3F393F6E3D393E386A3A3C396C"
LOGIN60_SKC = "L672YizCTm9CfnY5wWE64"
LOGIN60_LTK = "00OHlxAZQWvrX5SfE2WqYusL4RZovcdbmC4NbahD4"
LOGIN60_UA = "duapp/6.0.0(android;10)"
LOGIN60_WEBUA = "Dalvik/2.1.0 (Linux; U; Android 10; MIX 2S MIUI/V12.5.1.0.QDGCNXM)/duapp/6.0.0(android;10)"
LOGIN60_BRAND = "Xiaomi"
LOGIN60_TRAIT = "MIX+2S"        # dudeviceTrait 头真机字面值（webua 机型串里是 "MIX 2S" 空格）
LOGIN60_CHANNEL = "huawei"      # 真机渠道包标识（渠道与设备品牌解耦：华为渠道包装小米手机）
LOGIN60_UUID = "a668ae867143bb86"  # 真机 uuid 未知（init 响应无 iaid），保留旧值仅作 newSign 回落兜底

# ==================== 6.0 发布链路模拟器会话指纹（2026-10-18 模拟器手动登录后实抓） ====================
# 发布身份原则：token(JWT) 由哪个会话签发，headers 设备身份必须同会话——
# _dewu_token.json 的 token 来自模拟器 MI 8 手动登录（uuid=a668ae867143bb86 恰与 LOGIN60_UUID 相同），
# 混搭真机 MIX 2S 指纹 = 登录/发布撕裂。EMU60_* 与 _mitm_publish.jsonl 同源同值（全链路 154 签名验证通过）。
# ltk/adi 取抓包单样本值固定（真机/模拟器实证均每请求漂移、服务端不校验跨请求一致性）；
# dhw 仍每请求随机 52hex；stoken 为数美 90 长版（BQBq 前缀同 unionLogin 形态）。
EMU60_SK = "9UAHD6oygemz2H79oosvr5Nty462ZOpZp6oVr0N2rbi2MNxxv9IroefWB3vYehokY337eivguGZx1JIeFVQI4TDkLT1x"
EMU60_EDK = "6C7D61656D61352E6C7D7D7D616C35693E3E30696D303E3F393C3B6A6A303E2E6769616C35"
EMU60_SKC = "EY0zzKTJCtg9EE6bgvud4"
EMU60_LTK = "sC50a0G54h0MKi6jgOawTh9MyWoWyTkV41xbt7zE4"
EMU60_ADI = "X5cVnRqKwXHMxZKGwIBeGh7UegS2tx0hG9zMjZ2XPe0="
EMU60_STOKEN = "BQBq1EPLnrwGdQ-djmBpJsv9AcvwGfqnEQmG_TEnC_0AyuLUnXOrtGHpEyG5Yz6FD9bluMk9Hf1ce2FsuDb6ICVoCw"
EMU60_SHUMEIID = "20260909103243e7ee19258bb0ba121a409d5e929ce7c711a0303dfe68321c"
EMU60_UA = "duapp/6.0.0(android;9)"
EMU60_WEBUA = "Dalvik/2.1.0 (Linux; U; Android 9; MI 8 Build/PQ3A.190605.09022056)/duapp/6.0.0(android;9)"
EMU60_TRAIT = "MI+8"        # dudeviceTrait 头字面值（webua 机型串里是 "MI 8" 空格）
EMU60_MODEL = "MI8"         # OSS object_key 机型串（去空格）
EMU60_CHANNEL = "myapp"

# ==================== 5.60 自洽形态（发码链路专用，2026-09-12 破案） ====================
# 混搭=401 实锤：6.0 头 + 5.x 明文 body 同请求混搭被服务端签名层全量拒；
# v3.3 的 5.60 全套（Mi6 外壳+抓包旧值）同 IP 同时刻 485+code200 发码成功。
# 原则：按接口整体切换、零混搭——发码/init 纯 5.60；unionLogin 版本门禁(10001)
# 必须 6.0，登录链路自 init 6.0 拿自己的 token，绝不复用 5.60 会话 token。
VERSION_V560 = "5.60.0"
APP_BUILD_V560 = "5.60.0.10"
USER_AGENT_V560 = "duapp/5.60.0(android;10)"
FULL_UA_V560 = "Dalvik/2.1.0 (Linux; U; Android 10; Mi 6 Build/QD1A.190821.011)/duapp/5.60.0(android;10)"
UUID_V560 = "e450d85844d139e3"        # v3.3 抓包 uuid（newSign 硬编码源；独立常量防设备区覆盖）
EDK_V560 = "6C7D61656D61352E6C7D7D7D616C356D3C3D386C303D303C3C6C393B316D3B2E6769616C35"
SHUMEII_V560 = "20251124234603642360b7ffa2f2bad98b8078043e2d4200a02dc3f551a9e7"
SKC_INIT_V560 = "e4s8EFFXO353Fja08E044"
SKC_CAPTCHA_V560 = "fbL07A7wNc47Fq03D40d4"
ADI_CAPTCHA_V560 = "Q2pSb0xHVG1xSEVzQ1ZHMVLD6zXDRys4--p36VGRrAM="
LTK_INIT_V560 = "XO31PolBNuTACs51evLf9HBCIoWTDHhXUwRzHsqC1"
LTK_CAPTCHA_V560 = "IzOMA96myfElPwQKgLv2YIzqiHwtdhdA9nDFQbGB2"
IPVX_INIT_V560 = "39.186.143.131"     # v3.3 抓包固定IP（实证可用，不用动态IP）
NEWSIGN_INIT_V560 = "28a9415216323b97a5bca58d70e25fa7"  # v3.3 init 固定 newSign

import secrets as _secrets  # dhw/ss 每请求随机（真机同构）


# 数美sign（旧明文form sendCaptcha用，随body提交）
SIGN_FIXED = "7141a0b174c0282e3c7c93d999df751f"

# OSS签名服务（第三方）
OSS_SIGN_URL = "http://43.138.142.207:6668/auto_oss_v1_sign"

# 图片CDN
IMAGE_CDN = "https://image-cdn.poizon.com"

# WAF 会话 cookie（真机抓包实证：所有 dewu.com 请求带 Cookie: HWWAFSESID=..; HWWAFSESTIME=..，
# 由服务端首个响应 Set-Cookie 下发；init 响应捕获后全程复用。★485突破实证：双 cookie 全带
# 是突破要素之一——只带 HWWAFSESTIME 不够）
_WAF_COOKIE = {"v": "", "sid": ""}


def _capture_waf_cookie(response) -> None:
    """从响应捕获 HWWAFSESTIME/HWWAFSESID（cookies jar 优先，Set-Cookie 头兜底；幂等静默）"""
    try:
        for c in response.cookies:
            if c.name == "HWWAFSESTIME" and c.value:
                _WAF_COOKIE["v"] = c.value
            elif c.name == "HWWAFSESID" and c.value:
                _WAF_COOKIE["sid"] = c.value
        sc = response.headers.get("Set-Cookie", "") or ""
        if "HWWAFSESTIME=" in sc and not _WAF_COOKIE["v"]:
            _WAF_COOKIE["v"] = sc.split("HWWAFSESTIME=", 1)[1].split(";", 1)[0].strip()
        if "HWWAFSESID=" in sc and not _WAF_COOKIE["sid"]:
            _WAF_COOKIE["sid"] = sc.split("HWWAFSESID=", 1)[1].split(";", 1)[0].strip()
    except Exception:
        pass


def _waf_cookie_header() -> str:
    """拼 WAF Cookie 头（缺哪个省哪个；全空返回空串）"""
    parts = []
    if _WAF_COOKIE["sid"]:
        parts.append(f"HWWAFSESID={_WAF_COOKIE['sid']}")
    if _WAF_COOKIE["v"]:
        parts.append(f"HWWAFSESTIME={_WAF_COOKIE['v']}")
    return "; ".join(parts)


# 出口 IP（真机 ipvx 头 = 本机公网出口 IP；动态获取+缓存，网关重拨换 IP 后自动同步）
_PUBLIC_IP = {"v": "", "ts": 0.0}
_PUBLIC_IP_TTL = 600  # 缓存 10 分钟
_IPVX_FALLBACK = "14.212.23.140"  # 全部查询源失败时的兜底


def _public_ip() -> str:
    """当前公网出口 IP（缓存 10 分钟；失败静默回退旧值/兜底值，不阻塞业务请求）"""
    now = time.time()
    if _PUBLIC_IP["v"] and now - _PUBLIC_IP["ts"] < _PUBLIC_IP_TTL:
        return _PUBLIC_IP["v"]
    for url in ("https://api.ipify.org", "http://myip.ipip.net"):
        try:
            r = http_call("get", url, timeout=5)
            m = re.search(r"IP[：:]\s*([\d.]+)|^([\d.]+)$", r.text.strip(), re.M)
            v = (m.group(1) or m.group(2)) if m else ""
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v):
                _PUBLIC_IP["v"] = v
                _PUBLIC_IP["ts"] = now
                return v
        except Exception:
            continue
    return _PUBLIC_IP["v"] or _IPVX_FALLBACK


# ==================== 数据类 ====================
@dataclass
class DewuContext:
    """得物认证上下文"""
    token: str
    user_id: str
    # 空则运行时回落全局 DEFAULT_EDK（静态 MIX 2S 真机值，与 LOGIN60_EDK 同源）
    edk: str = ""
    user_name: str = ""
    # loginToken（unionLogin accessToken）：真机实证与 JWT 双 token 体系——
    # X-Auth-Token 用 JWT，duloginToken/cookieToken 头用 loginToken
    login_token: str = ""


@dataclass
class CaptchaResult:
    """验证码发送结果"""
    phone: str
    timestamp: str
    token: str
    encrypted_mobile: str
    new_sign: str
    response_text: str
    message: str
    success: bool
    challenge: Optional[dict] = None  # 485风控挑战 {"sessionId":..., "type":2}，非空时需滑块验证


@dataclass
class LoginResult:
    """登录结果"""
    phone: str
    user_id: str
    user_name: str
    token: str
    response_text: str
    success: bool
    headers: dict = None
    # unionLogin 的 accessToken（=loginToken），与 token(JWT) 配对保存
    login_token: str = ""
    # 附加说明（如游客态降级提示），前端优先显示
    message: str = ""
    # 485 风控挑战 {"sessionId":..., "type":2}：非空=unionLogin 被风控拦在验证码校验之前
    # （2026-09-12 http_log 真号实证：真码提交仍 485；真机码错是 20006 而非 485）
    challenge: Optional[dict] = None


@dataclass
class PublishResult:
    """发布结果"""
    success: bool
    response_text: str
    message: str
    content_id: str = ""
    article_url: str = ""
    http_status: int = 0


# ==================== AES加密 ====================
def _aes_encrypt(text: str, key: bytes) -> bytes:
    """AES-ECB加密"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode("utf-8")) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def _aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """AES-ECB解密"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode("utf-8")


def encrypt_hex(text: str) -> str:
    """AES加密后转十六进制"""
    return _aes_encrypt(text, DEWU_AES_HEX_KEY).hex()


def decrypt_hex(text: str) -> str:
    """十六进制解密"""
    return _aes_decrypt(bytes.fromhex(text), DEWU_AES_HEX_KEY)


def encrypt_base64(text: str) -> str:
    """AES加密后转Base64"""
    ciphertext = _aes_encrypt(text, DEWU_AES_BASE64_KEY)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_base64(text: str) -> str:
    """Base64解密"""
    ciphertext = base64.b64decode(text.encode("ascii"))
    return _aes_decrypt(ciphertext, DEWU_AES_BASE64_KEY)


# ==================== 工具函数 ====================
def current_timestamp_ms() -> str:
    """当前时间戳（毫秒）"""
    return str(int(time.time() * 1000))


def md5_utf8(text: str) -> str:
    """MD5哈希"""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def build_encrypted_mobile(phone: str) -> str:
    """加密手机号"""
    return encrypt_hex(phone) + "_1"


def random_guid_compact() -> str:
    """随机GUID（紧凑格式）"""
    return uuid.uuid4().hex


# ==================== newSign签名算法（通用，逆向实证版） ====================
# 规则：newSign = MD5(base64(AES-128-ECB-PKCS5(sortedKvStr)))，key=d245a0ba8d678a61
# 抓包验证：POST 850/850 + GET 651/651 全量命中
def newsign(source: str) -> str:
    """newSign = MD5(base64(AES-128-ECB-PKCS5(source)))"""
    return md5_utf8(encrypt_base64(source))


def _sign_flat(v) -> str:
    """签名源串取值：str原样/bool→true|false/list→逗号拼接/dict及其他→紧凑JSON"""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return ",".join(_sign_flat(e) for e in v)
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _session_uuid(token: str) -> str:
    """登录态请求签名用uuid：X-Auth-Token JWT payload的uuid，取不到回落固定值"""
    u = str(_decode_jwt_payload(token).get("uuid", "") or "")
    return u or UUID_FIXED


def build_post_new_sign(
    body: dict,
    timestamp: str,
    uuid_value: str = UUID_FIXED,
    duv: str = VERSION,
    login_token: str = "",
) -> str:
    """POST newSign：公共字段先放被body覆盖（body wins），loginToken缺省注入，key字典序拼接"""
    fields = {'uuid': uuid_value, 'platform': "android", 'v': duv, 'timestamp': timestamp}
    for k, v in body.items():
        if k in ("newSign", "sign"):
            continue
        fields[k] = v
    if 'loginToken' not in fields:
        fields['loginToken'] = login_token
    return newsign("".join(k + _sign_flat(fields[k]) for k in sorted(fields)))


def build_get_new_sign(
    query: dict,
    timestamp: str,
    uuid_value: str = UUID_FIXED,
    duv: str = VERSION,
    login_token: str = "",
) -> str:
    """GET newSign：query值二次percent-decode后被公共字段覆盖（抓包651/651实证），key字典序拼接"""
    fields = {}
    for k, v in query.items():
        if k in ("newSign", "sign"):
            continue
        fields[k] = urllib.parse.unquote(str(v))
    fields['uuid'] = uuid_value
    fields['platform'] = "android"
    fields['v'] = duv
    fields['loginToken'] = login_token
    fields['timestamp'] = timestamp
    return newsign("".join(k + fields[k] for k in sorted(fields)))


def build_captcha_new_sign(encrypted_mobile: str, timestamp: str) -> str:
    """发送验证码newSign——5.60 自洽形态（v3.3 硬编码 source 原样复刻）。
    与通用 build_post_new_sign 的区别：v 固定 5.60.0、uuid 固定抓包值、无 sign 字段。
    """
    source = (
        "cipherParammobilecountryCode86loginTokenmobile"
        + encrypted_mobile
        + "msgType0platformandroidriskTypeId1timestamp"
        + timestamp
        + "typeId1uuid" + UUID_V560 + "v" + VERSION_V560
    )
    return md5_utf8(encrypt_base64(source))


def build_login_new_sign(encrypted_mobile: str, captcha: str, timestamp: str) -> str:
    """验证码登录newSign（JSON body）——通用规则的薄封装"""
    body = {'cipherParam': "userName", 'code': captcha, 'countryCode': 86,
            'type': "code", 'userName': encrypted_mobile}
    return build_post_new_sign(body, timestamp)


# ==================== 请求头 ====================
def _init_headers(timestamp: str) -> dict:
    """client/init请求头——6.0 真机突破形态（_test_final_break 485实证，LOGIN60_* 常量）"""
    h = {
        'ltk': LOGIN60_LTK,
        'app_build': "6.0.0.10",
        'ipvx': _public_ip(),
        'cookieToken': "",
        'webua': LOGIN60_WEBUA,
        'duplatform': "android",
        'appId': "duapp",
        'duchannel': LOGIN60_CHANNEL,
        'humeChannel': "",
        'duv': VERSION,
        'duloginToken': "",
        'dudeviceTrait': LOGIN60_TRAIT,
        'dudeviceBrand': LOGIN60_BRAND,
        'timestamp': timestamp,
        'shumeiid': LOGIN60_SHUMEIID,
        'adi': LOGIN60_ADI,
        'User-Agent': LOGIN60_UA,
        'X-Auth-Token': "Bearer+",
        'isRoot': "0",
        'emu': "0",
        'isProxy': "1",
        # 6.0真机实证：sk/skt/dhwapp三头恒定必带（sk=数美SDK装机级会话密钥）
        'sk': LOGIN60_SK,
        'skt': DEVICE_SKT,
        'dhwapp': "dewu",
        'edk': LOGIN60_EDK,
        'dps': "1",
        'sks': "0,adw2",
        'skc': LOGIN60_SKC,
        # stoken（数美 native 下发，44短版）+ dhw（52hex 动态）：★init 干净 uuid 关键头
        'stoken': LOGIN60_STOKEN_INIT,
        'dhw': _secrets.token_hex(26),
        'Host': "m.dewu.com",
        'Connection': "Keep-Alive",
    }
    waf = _waf_cookie_header()
    if waf:
        h['Cookie'] = waf
    return h


def _init_headers_560(timestamp: str) -> dict:
    """client/init请求头——5.60 自洽形态（v3.3 原样复刻，发码链路专用）"""
    return {
        'ltk': LTK_INIT_V560,
        'app_build': APP_BUILD_V560,
        'ipvx': IPVX_INIT_V560,
        'cookieToken': "",
        'webua': urllib.parse.quote(FULL_UA_V560, safe=''),
        'duplatform': "android",
        'appId': "duapp",
        'duchannel': "oppo",
        'humeChannel': "",
        'duv': VERSION_V560,
        'duloginToken': "",
        'dudeviceTrait': "Mi+6",
        'dudeviceBrand': "Xiaomi",
        'timestamp': timestamp,
        'shumeiid': SHUMEII_V560,
        'User-Agent': urllib.parse.quote(USER_AGENT_V560, safe=''),
        'X-Auth-Token': "Bearer+",
        'isRoot': "0",
        'emu': "0",
        'isProxy': "0",
        'SK': "",
        'edk': EDK_V560,
        'dps': "1",
        'sks': "0%2Cadw2",
        'skc': SKC_INIT_V560,
        'Host': "m.dewu.com",
        'Connection': "Keep-Alive",
    }


def _captcha_headers_560(timestamp: str, token: str) -> dict:
    """发送验证码请求头——5.60 混合形态【已废弃：2026-10-09 复测 401，主链路发码已切白盒重放】：
    请求形态保持 5.60（User-Agent/duv/app_build/webua 用 5.60 值，防 400/11001），
    但设备身份字段（shumeiid/edk/adi/ltk/skc/duchannel/dudeviceTrait）对齐
    unionLogin 的 LOGIN60_*（2026-10-09 http_log 实证：同一 token 下发码 Mi6/5.60
    身份 + 登录 MI8/6.0 身份 → 指纹撕裂，服务端挂起会话返回 401/460"请稍后重试"）。
    """
    return {
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded",
        'Host': "app.dewu.com",
        'SK': "",
        'User-Agent': USER_AGENT_V560,
        'X-Auth-Token': token,
        'adi': LOGIN60_ADI,
        'appId': "duapp",
        'app_build': APP_BUILD_V560,
        'cookieToken': "",
        'dps': "1",
        'duchannel': LOGIN60_CHANNEL,
        'dudeviceBrand': "Xiaomi",
        'dudeviceTrait': LOGIN60_TRAIT,
        'duloginToken': "",
        'duplatform': "android",
        'duv': VERSION_V560,
        'edk': LOGIN60_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': "",
        'isProxy': "0",
        'isRoot': "0",
        'ltk': LOGIN60_LTK,
        'shumeiid': LOGIN60_SHUMEIID,
        'skc': LOGIN60_SKC,
        'sks': "0,adw2",
        'timestamp': timestamp,
        'webua': FULL_UA_V560,
    }


def _captcha_headers_60(timestamp: str, token: str) -> dict:
    """【仅诊断脚本引用】主链路不调用（2026-10-09 起主链路发码为白盒重放，见 send_dewu_captcha）。
    保留供复现 11001 实验：
    6.0头+5.60form body → 400 "校验失败：11001"，6.0 端点锁死 data= 白盒 body。

    发送验证码请求头——6.0 真机形态（_nsx_60_login_flow 2026-09-12 五样本实证）。
    以 _login_headers（unionLogin 485突破实证）为模板，差异项：
    - sks="1,adwx"（真机 sendCaptcha 专属；unionLogin 真机同为 0,adw2）
    - 新增 ss（32hex 随机，真机 sendCaptcha 每请求随机）
    - Content-Type 带 charset（真机形态）
    skc/adi/ltk 沿用 LOGIN60_* 会话自洽值：真机为白盒/数美 native 动态生成不可复现，
    与 init/unionLogin 同会话同值（自洽优先，485 突破实证同形态可行）。"""
    h = {
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded; charset=utf-8",
        'Host': "app.dewu.com",
        'sk': LOGIN60_SK,
        'skt': DEVICE_SKT,
        'dhwapp': "dewu",
        'User-Agent': LOGIN60_UA,
        'X-Auth-Token': token,
        'adi': LOGIN60_ADI,
        'appId': "duapp",
        'app_build': "6.0.0.10",
        'cookieToken': "",
        'dps': "1",
        'duchannel': LOGIN60_CHANNEL,
        'dudeviceBrand': LOGIN60_BRAND,
        'dudeviceTrait': LOGIN60_TRAIT,
        'duloginToken': "",
        'duplatform': "android",
        'duv': VERSION,
        'edk': LOGIN60_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': _public_ip(),
        'isProxy': "1",
        'isRoot': "0",
        'ltk': LOGIN60_LTK,
        'shumeiid': LOGIN60_SHUMEIID,
        'skc': LOGIN60_SKC,
        # 发码专属（真机五样本实证）：sks=1,adwx + ss=32hex 随机
        'sks': "1,adwx",
        'ss': _secrets.token_hex(16),
        'timestamp': timestamp,
        'webua': LOGIN60_WEBUA,
        # stoken（数美 native 90长版，与真机字面一致）+ dhw（52hex 每请求随机）
        'stoken': LOGIN60_STOKEN_LOGIN,
        'dhw': _secrets.token_hex(26),
    }
    # init响应下发的WAF cookie回传（真机6.0请求均带 Cookie: HWWAFSESTIME）
    waf = _waf_cookie_header()
    if waf:
        h['Cookie'] = waf
    return h


def _login_headers(timestamp: str, token: str) -> dict:
    """登录请求头——6.0 真机突破形态（_test_final_break unionLogin 485实证，LOGIN60_* 常量）"""
    h = {
        'Connection': "Keep-Alive",
        'Content-Type': "application/json; charset=utf-8",
        'Host': "app.dewu.com",
        # sk=数美SDK装机级会话密钥（真机装机值，LOGIN60_SK）
        'sk': LOGIN60_SK,
        'skt': DEVICE_SKT,
        'dhwapp': "dewu",
        'User-Agent': LOGIN60_UA,
        'X-Auth-Token': token,
        'adi': LOGIN60_ADI,
        'appId': "duapp",
        'app_build': "6.0.0.10",
        # unionLogin前游客无duToken（真机duToken由unionLogin成功后下发），保持空
        'cookieToken': "",
        'dps': "1",
        'duchannel': LOGIN60_CHANNEL,
        'dudeviceBrand': LOGIN60_BRAND,
        'dudeviceTrait': LOGIN60_TRAIT,
        'duloginToken': "",
        'duplatform': "android",
        'duv': VERSION,
        'edk': LOGIN60_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': _public_ip(),
        'isProxy': "1",
        'isRoot': "0",
        'ltk': LOGIN60_LTK,
        # 真机user_core抓包样本无rtk头（固定旧值+新随机设备=矛盾风控信号，10001主嫌疑）
        'shumeiid': LOGIN60_SHUMEIID,
        'skc': LOGIN60_SKC,
        'sks': "0,adw2",
        'timestamp': timestamp,
        'webua': LOGIN60_WEBUA,
        # stoken（数美 native 下发，90长版）+ dhw（52hex 动态）：★unionLogin 突破关键头
        'stoken': LOGIN60_STOKEN_LOGIN,
        'dhw': _secrets.token_hex(26),
    }
    # init响应下发的WAF cookie回传（真机6.0请求均带Cookie，会话连续性）
    waf = _waf_cookie_header()
    if waf:
        h['Cookie'] = waf
    return h


def _ensure_bearer(tok: str) -> str:
    """token 规范化为 'Bearer <JWT>'（真机实证 X-Auth-Token 形态；幂等）"""
    t = (tok or "").strip()
    if not t:
        return ""
    if t.startswith("Bearer "):
        return t
    return f"Bearer {t}"


def dewu_auth_headers(context: DewuContext, timestamp: str = None) -> dict:
    """登录态请求头——发布链路专用，设备身份切换为模拟器会话指纹（EMU60_*，
    2026-10-18 模拟器手动登录实抓；token 由该模拟器会话签发，同源防撕裂）。
    6.0 恒定头 sk/skt/dhwapp/stoken/dhw 全带。timestamp 须与 newSign 用的同一毫秒。
    cookieToken/duloginToken 用复合 loginToken（抓包实锤：发布会话所有 sns 请求均为复合串）。"""
    ts = timestamp or current_timestamp_ms()
    # 抓包实证：duloginToken 头 = duToken|uid|iat|<40hex>|1-0|<16hex>（len=242），非裸 duToken
    lt = dewu_composite_login_token(context) if (getattr(context, 'login_token', '') or '').strip() else ''
    h = {
        'Connection': "Keep-Alive",
        'sk': EMU60_SK,
        'skt': DEVICE_SKT,
        'dhwapp': "dewu",
        'User-Agent': EMU60_UA,
        'X-Auth-Token': _ensure_bearer(context.token),
        'adi': EMU60_ADI,
        'appId': "duapp",
        'app_build': "6.0.0.10",
        'cookieToken': lt,
        'dps': "1",
        'duchannel': EMU60_CHANNEL,
        'dudeviceBrand': LOGIN60_BRAND,
        'dudeviceTrait': EMU60_TRAIT,
        'duloginToken': lt,
        'duplatform': "android",
        'duv': VERSION,
        'edk': context.edk or EMU60_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': _public_ip(),
        'isProxy': "1",
        'isRoot': "0",
        'ltk': EMU60_LTK,
        'shumeiid': EMU60_SHUMEIID,
        'skc': EMU60_SKC,
        'sks': "0,adw2",
        'timestamp': ts,
        'webua': EMU60_WEBUA,
        'stoken': EMU60_STOKEN,
        'dhw': _secrets.token_hex(26),
    }
    waf = _waf_cookie_header()
    if waf:
        h['Cookie'] = waf
    return h


# ==================== 核心API ====================
def get_init_token(timestamp: Optional[str] = None, timeout: int = 20) -> str:
    """
    获取初始化token（X-Auth-Token）——5.60 自洽形态（v3.3 原样复刻，发码链路专用）。
    固定 newSign/ipvx 均为 v3.3 抓包值（动态 GET 签名属 6.0 形态，勿混用）。
    """
    timestamp = timestamp or current_timestamp_ms()
    url = (f"http://m.dewu.com/client/init?webUserAgent=&ipvx={IPVX_INIT_V560}"
           f"&isNewInstall=0&newSign={NEWSIGN_INIT_V560}")

    # 自动重试：超时/断连/5xx/未下发token 重试(间隔3秒)；4xx明确拒绝不重试
    last_err: Exception = RuntimeError("init未执行")
    for attempt in range(3):
        try:
            response = http_call("get", url, headers=_init_headers_560(timestamp), timeout=timeout)
            _capture_waf_cookie(response)
            token = response.headers.get("X-Auth-Token", "")
            if token:
                return token
            if 400 <= response.status_code < 500:
                response.raise_for_status()  # 得物明确拒绝（401/485等），重试无意义
            last_err = RuntimeError(
                f"init未下发X-Auth-Token: http={response.status_code} body={response.text[:200]}"
            )
        except (requests.Timeout, requests.ConnectionError) as e:
            last_err = e
        if attempt < 2:
            time.sleep(3)
    raise last_err


def get_init_token_60(timestamp: Optional[str] = None, timeout: int = 20) -> str:
    """获取初始化token——6.0 形态（登录链路专用）。
    unionLogin 版本门禁(10001)要求 6.0，token 必须来自 6.0 init 会话，
    复用 5.60 发码 token 即跨链路混搭（401 根因同源）。
    """
    # 自动重试：超时/断连/5xx/未下发token 重试(间隔3秒)；4xx明确拒绝不重试
    last_err: Exception = RuntimeError("init未执行")
    for attempt in range(3):
        try:
            ts = current_timestamp_ms()
            query = {'webUserAgent': "", 'ipvx': _public_ip(), 'isNewInstall': "0"}
            new_sign = build_get_new_sign(query, ts)
            # ★必须 https 直连（_test_final_break 485突破实证）：http 会 301 重定向，
            # 重定向链路服务端业务 200 但不下发 X-Auth-Token
            url = "https://m.dewu.com/client/init?" + urllib.parse.urlencode(
                {**query, 'newSign': new_sign})
            response = http_call("get", url, headers=_init_headers(ts), timeout=timeout)
            _capture_waf_cookie(response)
            token = response.headers.get("X-Auth-Token", "")
            if token:
                return token
            if 400 <= response.status_code < 500:
                response.raise_for_status()  # 得物明确拒绝（401/485等），重试无意义
            last_err = RuntimeError(
                f"init未下发X-Auth-Token: http={response.status_code} body={response.text[:200]}"
            )
        except (requests.Timeout, requests.ConnectionError) as e:
            last_err = e
        if attempt < 2:
            time.sleep(3)
    raise last_err


def exchange_jwt_token(login_token: str, timeout: int = 20) -> str:
    """登录态 client/init：用 loginToken 换 X-Auth-Token JWT。

    真机#289 抓包实证：请求带 duloginToken/cookieToken/Cookie:duToken=<loginToken>
    （+旧JWT），响应头直接下发续期后的 X-Auth-Token: Bearer <RS256 JWT>。
    登录刚完成时无旧JWT，仅带 loginToken 三件套请求。
    返回裸 JWT（去 Bearer 前缀），失败抛异常。
    """
    if not login_token:
        raise ValueError("login_token 为空，无法换取 JWT")
    timestamp = current_timestamp_ms()
    query = {'webUserAgent': "", 'ipvx': _public_ip(), 'isNewInstall': "0"}
    new_sign = build_get_new_sign(query, timestamp, login_token=login_token)
    url = "https://m.dewu.com/client/init?" + urllib.parse.urlencode(
        {**query, 'newSign': new_sign})
    headers = _init_headers(timestamp)
    headers['duloginToken'] = login_token
    headers['cookieToken'] = login_token
    headers['Cookie'] = f"duToken={login_token}"

    response = http_call("get", url, headers=headers, timeout=timeout)
    _capture_waf_cookie(response)
    response.raise_for_status()
    tok = (response.headers.get("X-Auth-Token")
           or response.headers.get("Authorization") or "").strip()
    if not tok:
        raise RuntimeError("登录态 init 响应头无 X-Auth-Token（响应体前200: "
                           f"{response.text[:200]!r}）")
    # 响应头形如 "Bearer eyJ..."，统一去掉前缀存裸 JWT
    if tok.startswith("Bearer "):
        tok = tok[len("Bearer "):]
    return tok


# ==================== 发码白盒重放常量（2026-10-09 真机抓包1331行原样固化） ====================
# 重放实证（_replay_captcha/_replay_captcha2 两次 HTTP485+code200=发码成功）：
# - data= 白盒体可重放：服务端不校验新鲜度，抓包数小时后原样重发照样出码
# - 不绑定 token：换工具自取的新鲜 init token（get_init_token_60）照常成功
# - 手机号加密在 data= 密文内：发码目标固定为抓包时真机输入的号码（本账号手机号）
# 由此发码全链路 6.0 真机指纹（init/发码/登录均为 MIX 2S），彻底替代 5.60 混合形态
# （5.60 外壳 2026-10-09 复测 401 签名认证失败，已废弃）
CAPTCHA_REPLAY_URL = 'https://app.dewu.com/api/v1/app/user/ice/user/sendCaptcha?newSign=f7f20e1cb3520f0604849e63a557e1d4'
CAPTCHA_REPLAY_HEADERS = {
    'Accept-Encoding': 'gzip',
    'Connection': 'Keep-Alive',
    'Content-Length': '409',
    'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
    'Cookie': 'HWWAFSESTIME=1791492992107',
    'Host': 'app.dewu.com',
    'SK': '9UBtS5z3fsHiAWZCZzCpHFXxNDZFBH0jGe1JhHCRWZnMoa4ZTG0WORo63hprSuBYYWrufI38slrbNm0ELODhT6E2NN1s',
    'User-Agent': 'duapp/6.0.0(android;10)',
    'X-Auth-Token': '',  # 运行时用 get_init_token_60 新鲜 token 覆盖
    'adi': 'GcT7yA3LSqYiCtb622Wv-mY4-nJXU6-TFwaw8qK8_jQ=',
    'appId': 'duapp',
    'app_build': '6.0.0.10',
    'cookieToken': '',
    'dhw': 'a1ecc66a0e7e00e87400d2bf7477b54deefb7fbe41bad4ea5f8d',
    'dhwapp': 'dewu',
    'dps': '1',
    'duchannel': 'huawei',
    'dudeviceBrand': 'Xiaomi',
    'dudeviceTrait': 'MIX+2S',
    'duloginToken': '',
    'duplatform': 'android',
    'duv': '6.0.0',
    'edk': '6C7D61656D61352E6C7D7D7D616C353B3B6C3D3B6D386D3C693D3E3C6A6C3C2E6769616C356E6C3A3F393F6E3D393E386A3A3C396C',
    'emu': '0',
    'humeChannel': '',
    'ipvx': '14.212.31.232',
    'isProxy': '1',
    'isRoot': '0',
    'ltk': 'TTHAeqtSJPokLlyuPBdCbj52VKSho564fv4NbahDd',
    'shumeiid': '2026100904563362f7a65c484d2a8fd0ddb902fadd8b5d00a024190b795f4b',
    'skc': 'bGHCoS9cjWJcFXyFWweGuAACV74gBATAq4A4',
    'sks': '1,adwx',
    'skt': 'adr1',
    'ss': 'de2a123c19830df2480d34764fb5d54f',
    'stoken': 'BQBqyAOCmGjxwATfetW2qbBzQmu25JAaTkkEJpZlTnTLshrQW82CRroQoGMpQm5EfpZZkH0I_rqN-bVQCdgDiM1WxQ',
    'timestamp': '1791493028677',
    'webua': 'Dalvik/2.1.0 (Linux; U; Android 10; MIX 2S MIUI/V12.5.1.0.QDGCNXM)/duapp/6.0.0(android;10)',
}
CAPTCHA_REPLAY_BODY = 'data=M0E5NzQ3MTJDRjVEQUE1NDIxQTRBMzkzRkM3RDM5NjIuY0dGeVlXMGZObVUyTjJJeU9UY3RZVE5qWWkwMFl6SmxMV0ZqWldNdE1tWTFaRGc1Wm1OaE0yVXdIblpsY25OcGIyNGZNUjV3YkdGMFptOXliUjloYm1SeWIybGtIbVZqSHpFPS6OVR4HveBr3OtD24NynwBdcklk_i8o_nyiFcqzZsd4H3htMu7BMko0vlyazTHOegkD9xR_JedwbLpczc5gwytb2ayldbsuUWrqQ8yVd5Q9Syikfi0Vxs3i_QbGimqfO2lGXwTEbQAwibIJytxxky5X5DgzZK4rJTbtU8vMZ895DFUlSClgUL0L61PNnGfCKFy-Qe8kt6w3jdtlr_oC-kk5GcT7yPo5SQI='
CAPTCHA_BOUND_PHONE = ""  # 发码绑定手机号（抓包时真机输入的号码）；置空跳过校验


def send_dewu_captcha(phone: str, init_token: Optional[str] = None, timeout: int = 20) -> CaptchaResult:
    """
    发送验证码——6.0 纯形态（白盒 data= 原样重放，2026-10-09 重放实验定型）。

    请求 = 真机抓包1331行原样（CAPTCHA_REPLAY_*），仅 X-Auth-Token 换
    get_init_token_60 的新鲜 token（重放实证：data= 可重放、不绑定 token）。
    手机号加密在 data= 密文内、服务端按密文发码——目标号码固定为抓包时
    真机输入的号码；phone 参数仅作记录，CAPTCHA_BOUND_PHONE 非空时校验一致。
    init_token 可复用上次 token（485滑块验证后重试时与抓包行为一致：同会话token重发）
    """
    if CAPTCHA_BOUND_PHONE and phone != CAPTCHA_BOUND_PHONE:
        raise ValueError(
            f"发码目标固定为真机绑定号码 {CAPTCHA_BOUND_PHONE}（data= 白盒密文不可改号），"
            f"传入 {phone} 与之不符")
    timestamp = current_timestamp_ms()
    token = init_token or get_init_token_60(timestamp, timeout=timeout)
    encrypted_mobile = build_encrypted_mobile(phone)  # 仅记录；实际发码号码由 data= 密文绑定
    new_sign = CAPTCHA_REPLAY_URL.split("newSign=")[-1]

    headers = dict(CAPTCHA_REPLAY_HEADERS)
    headers['X-Auth-Token'] = token

    response = http_call("post",
        CAPTCHA_REPLAY_URL,
        data=CAPTCHA_REPLAY_BODY.encode('utf-8'),
        headers=headers,
        timeout=timeout,
        allow_redirects=True,
    )
    _capture_waf_cookie(response)

    # 485是HTTP状态码（风控层标记），body可能仍是业务结果，不能直接raise
    # 实测两形态：HTTP485+body code485(data=dict含sessionId)=挑战；HTTP485+body code200(data=加密串)=业务成功
    if response.status_code == 485:
        text = urllib.parse.unquote(response.text)
        body_code = ""
        data_is_token = False
        challenge = None
        try:
            rj = json.loads(text)
            body_code = str(rj.get("code") or "")
            d = rj.get("data")
            data_is_token = isinstance(d, str) and bool(d)
            if isinstance(d, dict) and d.get("sessionId"):
                challenge = {'sessionId': d["sessionId"], 'type': d.get("type")}
        except Exception:
            pass
        if body_code == "200" and data_is_token:
            return CaptchaResult(
                phone=phone,
                timestamp=timestamp,
                token=token,
                encrypted_mobile=encrypted_mobile,
                new_sign=new_sign,
                response_text=text,
                message="验证码已发送",
                success=True,
            )
        return CaptchaResult(
            phone=phone,
            timestamp=timestamp,
            token=token,
            encrypted_mobile=encrypted_mobile,
            new_sign=new_sign,
            response_text=text,
            message="请校验验证码（风控滑块）",
            success=False,
            challenge=challenge,
        )

    response.raise_for_status()

    text = urllib.parse.unquote(response.text)
    message = _extract_response_message(text)
    response_code = _extract_json_value(text, "code") or _extract_json_value(text, "status")
    success = ("验证码已发送" in text or str(response_code) == "200")

    # 485风控挑战：提取sessionId（滑块会话ID，app_call/app_verify时回传）
    challenge = None
    if str(response_code) == "485":
        try:
            rj = json.loads(text)
            cd = rj.get("data") or {}
            if cd.get("sessionId"):
                challenge = {'sessionId': cd["sessionId"], 'type': cd.get("type")}
        except Exception:
            pass

    return CaptchaResult(
        phone=phone,
        timestamp=timestamp,
        token=token,
        encrypted_mobile=encrypted_mobile,
        new_sign=new_sign,
        response_text=text,
        message=message,
        success=success,
        challenge=challenge,
    )


# ==================== 风控滑块（risk-stone-captcha） ====================
# 抓包实证（_ns67/_ns69/_ns71）：app_call 支持明文JSON（sessionID即485返回的sessionId）；
# app_verify body = {"d":<加密轨迹>,"sign":<md5>,"sessionID":...,"lang":"zh","platform":"android","a":"0"}
# 请求头极简：bcn/pix/sk + Dalvik UA，无newSign/X-Auth-Token
def _risk_stone_headers() -> dict:
    return {
        'Content-Type': "application/json",
        'User-Agent': FULL_UA,
        'bcn': "dewu",
        'pix': "2,adw2",
        'sk': DEVICE_SK,
    }


def risk_stone_call(session_id: str, timeout: int = 20) -> dict:
    """拉取滑块/点选挑战图。返回服务端JSON：bgImage=滑块单图；bgList=点选多图（首张为blank占位）"""
    body = {
        'a': "0",
        'bcn': "dewu",
        'dss': "1080,1920,3.0",
        'sessionID': session_id,
        'lang': "zh",
        'sk': DEVICE_SK,
        'platform': "android",
        'type': "0",
        'userid': "",
        'dtu': "huawei",
        'iaid': UUID_FIXED,
        'bcv': "1.2.5.240909",
        'webp': "1",
    }
    r = http_call("post", 
        "https://app.dewu.com/api/app/risk-stone-captcha/captcha/app_call",
        json=body,
        headers=_risk_stone_headers(),
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


# ==================== 滑块轨迹构造（u6 静态实锤格式） ====================
# sld 格式（ScrollBean.toString smali + #11029 成功样本逐字符实锤）：
#   事件 = t=<ms>,e=<d|s|k>,x=<f>,y=<f>,s=<f>,p=<f>，事件间用 "|" 分隔（非\n）
#   首事件 t=绝对时间戳，后续 t=距上一事件的毫秒增量
#   e=d 按下 / e=s 移动（s=0.0,p=0.5）；e=k 抬起（x=y=s=p 全 0.0）
#   x/y 直接是屏幕像素浮点（无需密度换算）
# dgyro 格式：每条 "t,x,y,z"（首条绝对ts，后续 delta），竖线分隔；静止设备 x=y=0
# c 字段：ver=<bcv>|opt=0|reqt=<app_call请求ts>|rest=555|vreqt=<n>|vrest=<n>|sqt=<n>|ck=<md5(sld)>
#   ck=md5(sld) 已由成功样本 #11029 逐字符实锤（_u6p/_u6q）；verify 请求无独立 ck 字段
# d/sign：仍在 libGameVMP VMP native 内组装加密（Java/dex 层零参与已实证 _u6s~_u6y），
#   需动态方案提供（frida hook Il11IIl1lll HTTP 回调可截获完整 body）
_RISK_BCV = "1.2.5.240909"   # captcha SDK 版本
_RISK_BAV = "6.0.0"          # 真机成功样本所属 app 版本（6.har/32132.har 实证）


def _jfloat(v) -> str:
    """Java Float.toString 风格：最短表示，整数带 .0"""
    s = f"{float(v):.6f}".rstrip("0")
    return s + "0" if s.endswith(".") else s


def build_sld_trace(events, start_ts=None) -> str:
    """
    构造 sld 轨迹串。
    events: [(t, "d"|"s"|"k", x, y), ...] — 首个 t 为绝对毫秒时间戳（None=当前时间），
            后续 t 为与上一事件的间隔毫秒。e=k 自动坐标清零。
    """
    if start_ts is None:
        start_ts = int(events[0][0])  # 首事件自带绝对时间戳
    parts = []
    for i, (t, e, x, y) in enumerate(events):
        t = start_ts if i == 0 else int(t)
        if e == "k":
            x = y = 0.0
        p = "0.0" if e == "k" else "0.5"
        parts.append(f"t={t},e={e},x={_jfloat(x)},y={_jfloat(y)},s=0.0,p={p}")
    return "|".join(parts)


def build_dgyro_trace(samples, start_ts=None) -> str:
    """
    构造 dgyro 串。samples: [(t, x, y, z), ...] — 首条 t 为绝对毫秒时间戳
    （None=当前时间），后续为增量。静止设备建议 x=y=0, z=微小噪声。
    """
    if start_ts is None:
        start_ts = int(samples[0][0])  # 首条自带绝对时间戳
    return "|".join(
        f"{start_ts if i == 0 else int(t)},{x},{y},{z}"
        for i, (t, x, y, z) in enumerate(samples)
    )


def build_risk_c(sld: str, reqt_ms, vreqt: int = 62, vrest: int = 165,
                 sqt: int = 7569, rest: int = 555) -> str:
    """构造 verify 的 c 字段；ck=md5(sld)（成功样本实锤）"""
    ck = hashlib.md5(sld.encode("utf-8")).hexdigest()
    return (f"ver={_RISK_BCV}|opt=0|reqt={reqt_ms}|rest={rest}"
            f"|vreqt={vreqt}|vrest={vrest}|sqt={sqt}|ck={ck}")


def risk_stone_verify(
    session_id: str,
    d_payload: str,
    sign: str,
    sld: str,
    dgyro: str = "",
    reqt_ms=None,
    dbs_ts=None,
    timeout: int = 20,
) -> dict:
    """
    提交滑块轨迹验证（29 字段完整版，对齐 #11029 成功样本）。
    d=加密轨迹串（libGameVMP 内生成，需动态提供）；sign=32hex（同左）；
    sld=build_sld_trace 输出；dgyro=build_dgyro_trace 输出；
    reqt_ms=app_call 请求时刻毫秒；dbs_ts=会话开始毫秒。
    成功响应：{"code":1,"msg":"验证成功","isAly":-1}
    """
    now_ms = int(time.time() * 1000)
    if reqt_ms is None:
        reqt_ms = now_ms
    if dbs_ts is None:
        dbs_ts = now_ms - 105000  # 真机样本：dbs 早于 sld 约 105s
    body = {
        'd': d_payload,
        'sign': sign,
        'sessionID': session_id,
        'lang': "zh",
        'platform': "android",
        'a': "0",
        'bcn': "dewu",
        'dss': "1080,1920,3.0",
        'sk': DEVICE_SK,
        'bssm': "",
        'userid': "",
        'dtu': "vivo",
        'iaid': "a668ae867143bb86",
        'mf': "3,1,0,1",
        'sld': sld,
        'bcv': _RISK_BCV,
        'webp': "1",
        'bav': _RISK_BAV,
        'dbs': f"100,3650,322,2,1,{dbs_ts}",
        'lism': "0",
        'lisr': "1",
        'lish': "0",
        'dme': "MI 8",
        'nabi': "x86_64",
        'dhw': "qcom",
        'dsb': "102",
        'dbra': "Xiaomi",
        'dgyro': dgyro,
        'c': build_risk_c(sld, reqt_ms),
    }
    r = http_call("post", 
        "https://app.dewu.com/api/app/risk-stone-captcha/captcha/app_verify",
        json=body,
        headers=_risk_stone_headers(),
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def login_dewu_with_captcha(
    phone: str,
    captcha: str,
    timeout: int = 20,
    init_token: Optional[str] = None,
) -> LoginResult:
    """
    验证码登录得物——6.0 自洽形态。
    token 必须来自 6.0 init（get_init_token_60）：unionLogin 版本门禁(10001)锁 6.0。
    ★会话统一（真机抓包同 token 贯穿 init→sendCaptcha→unionLogin；
    _test_full_chain60 假号全链路实证同 token 业务层受理）：
    验证码会话按 token+手机号匹配，init_token 传发码时的 token 复用同一会话；
    缺省自 init 拿新 token（仅诊断/独立调用，跨会话服务端可能查无验证码）。
    """
    extra_message = ""  # 游客态降级等附加提示，传给前端优先显示
    timestamp = current_timestamp_ms()
    token = init_token or get_init_token_60(timestamp, timeout=timeout)
    encrypted_mobile = build_encrypted_mobile(phone)

    url = "https://app.dewu.com/api/v1/app/user_core/users/unionLogin"
    payload = {
        'cipherParam': "userName",
        'code': captcha,
        'countryCode': 86,
        'loginToken': "",
        'platform': "android",
        'timestamp': str(timestamp),  # 真机抓包实证：user_core body的timestamp是字符串
        'type': "code",
        'userName': encrypted_mobile,
        'v': VERSION,
    }
    # ★401根因修复（_test_final_break 485突破实证）：newSign 签名材料里的 uuid
    # 必须等于 X-Auth-Token JWT payload 的 uuid（服务端做 uuid↔token 绑定校验），
    # 否则 401；重签后 485 业务层通过。
    new_sign = build_post_new_sign(payload, timestamp, uuid_value=_session_uuid(token))
    # 真机getVisitorUserId样本实证：user_core域newSign放body（ice域sendCaptcha才放query）
    payload['newSign'] = new_sign

    response = http_call("post",
        url,
        json=payload,
        headers=_login_headers(timestamp, token),
        timeout=timeout,
        allow_redirects=True,
    )
    _capture_waf_cookie(response)
    # 485 双形态判别（2026-09-12 http_log.txt 真号实证）：
    # - data 含 sessionId+type:2 = 风控滑块挑战：unionLogin 被拦在验证码校验之前，
    #   真码提交后同样 485；真机抓包码错返回 20006，故 485≠码错
    # - 无 sessionId = 业务层"验证码无效/未发送"（签名/风控已通过，_test_final_break 旧认知）
    if response.status_code == 485:
        challenge = None
        msg485 = "请校验验证码"
        try:
            rj485 = response.json()
            msg485 = rj485.get("msg") or msg485
            d485 = rj485.get("data")
            if isinstance(d485, dict) and d485.get("sessionId"):
                challenge = {"sessionId": d485.get("sessionId", ""), "type": d485.get("type", 2)}
        except Exception:
            pass
        log(f'unionLogin 485: {response.text[:200]}'
            + (' [风控滑块挑战,验证码未校验]' if challenge else ' [业务层验证码无效]'))
        return LoginResult(
            phone=phone, user_id="", user_name="", token="",
            response_text=response.text, success=False,
            headers=dict(response.headers), login_token="",
            message=(f"{msg485}：触发风控滑块验证，验证码未被校验"
                     if challenge else
                     f"{msg485}：验证码无效或未发送（签名/风控校验已通过）"),
            challenge=challenge,
        )
    # 401 分支（2026-10-09 实证：body 为 {"code":460,"msg":"请稍后重试"} 等，
    # HTTP 层 401 + 业务层 460 = 签名已通过但会话被风控挂起，多为设备指纹异常
    # 或请求过频。直接抛异常会导致上层拿不到结构化结果）
    if response.status_code == 401:
        msg401 = response.text[:200]
        try:
            rj401 = response.json()
            msg401 = f'{rj401.get("code", "?")}/{rj401.get("msg") or response.text[:100]}'
        except Exception:
            pass
        log(f'unionLogin 401: {msg401} [会话被挂起，签名已通过]')
        return LoginResult(
            phone=phone, user_id="", user_name="", token="",
            response_text=response.text, success=False,
            headers=dict(response.headers), login_token="",
            message=(f"登录被拒({msg401})：会话被风控挂起，多为设备指纹异常或请求过频，"
                     "请更换网络/IP 或稍后再试"),
            challenge=None,
        )
    response.raise_for_status()

    text = urllib.parse.unquote(response.text)
    code = _extract_tag(text, "code") or _extract_json_value(text, "code")
    auth_token = (
        response.headers.get("X-Auth-Token", "")
        or response.headers.get("Authorization", "")
    ).strip()

    # 20006 = 验证码错误（2026-09-12 最新真机抓包 #659 实证：验证码输错时返回 20006；
    # 其响应内的 accessToken 为游客态降级凭证，非登录成功——旧"20006=成功"认知已废弃）
    success = (str(code) == "200")
    login_token_val = ""
    if str(code) == "20006" and not auth_token:
        success = False
        extra_message = "验证码错误（20006），请核对后重新输入"
        log(f'unionLogin 20006: {text[:200]}')

    jwt_payload = _decode_jwt_payload(auth_token)
    user_id = (
        _extract_tag(text, "userId")
        or _extract_json_value(text, "userId")
        or str(jwt_payload.get("userId", ""))
    )
    user_name = (
        _extract_tag(text, "userName")
        or _extract_json_value(text, "userName")
        or str(jwt_payload.get("userName", ""))
    )

    return LoginResult(
        phone=phone,
        user_id=user_id,
        user_name=user_name,
        token=auth_token,
        response_text=text,
        success=success,
        headers=dict(response.headers),
        login_token=login_token_val,
        message=extra_message,
    )


def _heracles_extract_access_token(resp_text: str) -> str:
    """从 20006 响应解出 accessToken（heracles 加密 data 字段）"""
    try:
        j = json.loads(resp_text)
    except json.JSONDecodeError:
        return ""
    enc = j.get("data") if isinstance(j, dict) else None
    if not isinstance(enc, str) or not enc:
        return ""
    try:
        plain = _heracles_decrypt(enc)
    except Exception:
        return ""
    try:
        pj = json.loads(plain)
        tok = ((pj.get("data") or {}).get("accessToken")) if isinstance(pj, dict) else None
        return str(tok) if tok else ""
    except json.JSONDecodeError:
        return ""


def _plain_fail_msg(resp_text: str) -> str:
    """失败响应提取中文原因：外层 msg 优先，heracles 加密 data 内的 msg 解密兜底。

    服务端失败响应形如 {"code":794,"data":"<b64url密文>","status":794}，
    msg 藏在加密 data 里（外层只有 code/status），不解密就是一串乱码。
    引擎缺失/解密失败时静默回退，不影响调用方主流程。
    """
    try:
        j = json.loads(resp_text)
    except Exception:
        return resp_text[:150]
    if not isinstance(j, dict):
        return resp_text[:150]
    code = str(j.get('code') or j.get('status') or '')
    outer_msg = j.get('msg') or ''
    enc = j.get('data')
    if isinstance(enc, str) and enc:
        try:
            plain = _heracles_decrypt(enc)
            pj = json.loads(plain)
            if isinstance(pj, dict) and pj.get('msg'):
                return f"{pj['msg']}（code {code}）" if code else str(pj['msg'])
        except Exception:
            pass
    if outer_msg:
        return f"{outer_msg}（code {code}）" if code else str(outer_msg)
    return f"code {code}（响应未含msg）" if code else resp_text[:150]


# ==================== heracles 解密（引擎：加速 boot + 0x4694 JNI 全链路） ====================
# 结构实证（_u8z* 系列 + _u8zzH/_u8zzi）:
#   raw = b64url 解码；头 33B + N×8B 密文块；密钥(key16)/IDEA 表按响应派生
#   引擎 = _heracles_engine：加速 boot（DT_INIT count 截断，秒级）后直调 0x4694，
#   完整走 key16 派生 + 表派生 + IDEA 块解密；跨响应验证 20006旧/18:44新/SMS 全中
_HERACLES_ENGINE = None


def _heracles_decrypt(enc_b64url: str) -> str:
    """heracles 解密：b64url 密文 -> 明文 JSON（引擎跨响应 3/3 验证）"""
    s = enc_b64url.strip()
    s += "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(s)
    if len(raw) < 41 or (len(raw) - 33) % 8:
        raise ValueError(f"heracles 密文长度异常: {len(raw)}")
    from _heracles_engine import heracles_decrypt as _hd
    return _hd(raw).decode("utf-8")


def get_oss_info(context: DewuContext, timeout: int = 20) -> dict:
    """
    获取OSS上传信息
    """
    timestamp = current_timestamp_ms()
    new_sign = build_get_new_sign({'cdnType': "2", 'scene': "content-publish-image"}, timestamp,
                                  uuid_value=_session_uuid(context.token))
    response = http_call("get",
        "https://app.dewu.com/sns-conf/v1/config/get-oss-info",
        params={'cdnType': "2", 'scene': "content-publish-image", 'newSign': new_sign},
        headers=dewu_auth_headers(context, timestamp),
        timeout=timeout,
        allow_redirects=True,
    )
    _capture_waf_cookie(response)
    if response.status_code != 200:
        # 401/403 等：服务端拒绝原因常在响应体（可能 heracles 加密），解出记录便于定位
        from modules.rizhi import log as _log
        _log(f'get-oss-info HTTP {response.status_code}，响应头token相关字段: '
             f'X-Auth-Token={bool(response.headers.get("X-Auth-Token"))} sks={response.headers.get("sks")}')
        _log(f'get-oss-info 响应体: {response.text[:500]}')
        _log(f'get-oss-info 失败原因: {_plain_fail_msg(response.text)}')
    response.raise_for_status()
    data = response.json()
    # 服务端返回 {"code":200,"data":{AccessKeyId,AccessKeySecret,SecurityToken,...}} 信封结构，解出凭证层
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    return data


# ---------- 6.0 发布链路 OSS v2 预分配 + 两步上传（2026-10-18 抓包实证） ----------
# 时序：POST get-oss-info-v2(jpg fileInfos) -> PUT jpg 私有桶(acl=private，保真存档)
#       -> GET get-oss-info(v1) 取公开桶 STS -> PUT webp 公开桶（publish images 引用 webp CDN URL）
_LT_TAIL = "889fa5ae98b317c57b395e9b4d3fed31dc7eef99|1-0|b44021ce981a8ef4"  # 会话常量（抓包复刻，服务端语义未知）


def dewu_composite_login_token(context) -> str:
    """6.0 发布链路复合 loginToken：duToken|uid|jwt_iat|<40hex>|1-0|<16hex>。
    抓包全会话恒定（len=242）；iat 取登录时 JWT payload（_dewu_token.json 的 jwt_iat
    与抓包 seg2 完全一致）。已是复合串则原样返回（幂等）。"""
    lt = (getattr(context, 'login_token', '') or '').strip()
    if lt.startswith('duToken='):
        lt = lt[len('duToken='):]
    if '|' in lt:
        return lt
    iat = str(_decode_jwt_payload(getattr(context, 'token', '')).get('iat') or '') or str(int(time.time()))
    return f"{lt}|{context.user_id}|{iat}|{_LT_TAIL}"


def get_oss_info_v2(context: DewuContext, file_infos: list, timeout: int = 20) -> list:
    """OSS v2 预分配（POST JSON，scene=a3f7）：按图传实际 byte/w/h（jpg），
    返回 data.list（每项含 file=服务端预分配完整路径 + 小写驼峰 STS + bucketName/ossHost）"""
    timestamp = current_timestamp_ms()
    body = {
        'cp': "ali",
        'fileInfos': [
            {'byte': int(f['byte']), 'w': int(f['w']), 'h': int(f['h']), 'fileExtension': "jpg"}
            for f in file_infos
        ],
        'loginToken': dewu_composite_login_token(context),
        'newSign': "",
        'platform': "android",
        'scene': "a3f7",
        'timestamp': timestamp,
        'v': VERSION,
    }
    body['newSign'] = build_post_new_sign(body, timestamp, uuid_value=_session_uuid(context.token))
    response = http_call("post",
        "https://app.dewu.com/sns-oss/v1/config/get-oss-info-v2",
        json=body,
        headers=dewu_auth_headers(context, timestamp),
        timeout=timeout,
    )
    _capture_waf_cookie(response)
    response.raise_for_status()
    data = response.json()
    lst = data.get("data", {}).get("list") if isinstance(data, dict) else None
    if not isinstance(lst, list) or not lst:
        raise RuntimeError(f"get-oss-info-v2 响应异常: {str(data)[:300]}")
    return lst


def _put_oss_request(oss_info: dict, object_key: str, data, content_type: str,
                     oss_acl: str = "", timeout: int = 120) -> requests.Response:
    """OSS PUT（本地 V1 签名）。STS 键兼容 v1 大写(AccessKeyId)/v2 驼峰(accessKeyId)；
    oss_acl 非空时带 x-oss-object-acl（私有桶 jpg）。连接超时自动重试3次。"""
    from email.utils import formatdate
    access_key_id = oss_info.get("AccessKeyId") or oss_info.get("accessKeyId") or ""
    access_key_secret = oss_info.get("AccessKeySecret") or oss_info.get("accessKeySecret") or ""
    security_token = oss_info.get("SecurityToken") or oss_info.get("securityToken") or ""
    if not (access_key_id and access_key_secret and security_token):
        raise RuntimeError("OSS STS 凭证缺失")
    bucket = oss_info.get("bucketName") or "dewu-image"
    host = oss_info.get("customEndpoint") or oss_info.get("ossHost") or "dewu-image.oss-cn-shanghai.aliyuncs.com"
    if host and not host.startswith(("http://", "https://")):
        host = "https://" + host.rstrip("/")
    key = "/" + object_key.lstrip("/")
    oss_headers = {"x-oss-security-token": security_token}
    if oss_acl:
        oss_headers["x-oss-object-acl"] = oss_acl
    for attempt in range(3):
        date_str = formatdate(usegmt=True)
        signature = _oss_v1_sign("PUT", content_type, date_str, f"/{bucket}{key}", access_key_secret, oss_headers)
        headers = {
            'Authorization': f"OSS {access_key_id}:{signature}",
            'Date': date_str,
            'Content-Type': content_type,
        }
        headers.update(oss_headers)
        try:
            return http_call("put", f"{host}{key}", data=data, headers=headers, timeout=timeout)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
            else:
                raise


def _image_jpeg_bytes(image_path: Path) -> tuple:
    """(jpg_bytes, w, h)：jpg/jpeg 原字节直传（保真），其余 PIL RGB→JPEG q90 统一转码（BytesIO 不落盘）"""
    from io import BytesIO
    from PIL import Image
    if (image_path.suffix or "").lower() in (".jpg", ".jpeg"):
        try:
            raw = image_path.read_bytes()
            with Image.open(BytesIO(raw)) as im:
                w, h = im.size
            return raw, (w or 800), (h or 800)
        except Exception:
            pass
    with Image.open(image_path) as im:
        w, h = im.size
        buf = BytesIO()
        im.convert("RGB").save(buf, format="JPEG", quality=90)
        return buf.getvalue(), (w or 800), (h or 800)


def _image_webp_bytes(image_path: Path) -> tuple:
    """(webp_bytes, w, h)：PIL WEBP quality=100 method=6（publish 表单 images 引用 webp URL）"""
    from io import BytesIO
    from PIL import Image
    with Image.open(image_path) as im:
        w, h = im.size
        buf = BytesIO()
        im.save(buf, format="WEBP", quality=100, method=6)
        return buf.getvalue(), (w or 800), (h or 800)


def upload_image_to_oss(
    image_path: str,
    oss_info: dict,
    context: DewuContext,
    timeout: int = 120,
    log=lambda _msg: None,
    object_key: str = "",
) -> str:
    """
    上传图片到OSS，返回图片URL（publish images 引用的公开桶 webp CDN 地址）
    object_key 非空（视频封面等指定路径）→ 单步直传旧逻辑；
    为空（图文主图）→ 6.0 两步全链路：v2 预分配 → PUT jpg 私有桶 → 转 webp → PUT 公开桶
    """
    image_path = Path(image_path)
    if object_key:
        return _upload_image_legacy(image_path, oss_info, context, timeout, log, object_key)

    jpg_bytes, width, height = _image_jpeg_bytes(image_path)
    entries = get_oss_info_v2(context, [{'byte': len(jpg_bytes), 'w': width, 'h': height}])
    private_key = "/" + str(entries[0].get("file") or "").lstrip("/")
    resp = _put_oss_request(entries[0], private_key, jpg_bytes, "image/jpeg",
                            oss_acl="private", timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"私有桶jpg上传失败: HTTP {resp.status_code} {resp.text[:200]}")
    log("  私有桶jpg上传完成")

    webp_bytes, _, _ = _image_webp_bytes(image_path)
    webp_key = (
        f"/app/2026/community/{context.user_id}_model{EMU60_MODEL}model_byte{len(webp_bytes)}byte_"
        f"{hashlib.md5(webp_bytes).hexdigest()}_{current_timestamp_ms()}_du_android_w{width}_h{height}.webp"
    )
    for attempt in range(2):
        resp = _put_oss_request(get_oss_info(context), webp_key, webp_bytes, "image/webp", timeout=timeout)
        if resp.status_code == 200:
            return IMAGE_CDN + webp_key
        if attempt == 0 and _is_oss_security_token_expired(resp.status_code, resp.text):
            log("  webp STS 过期，刷新重试")
            continue
        raise RuntimeError(f"webp上传失败: HTTP {resp.status_code} {resp.text[:200]}")
    raise RuntimeError("webp上传失败（STS 刷新后仍失败）")


def _upload_image_legacy(
    image_path,
    oss_info: dict,
    context: DewuContext,
    timeout: int = 120,
    log=lambda _msg: None,
    object_key: str = "",
) -> str:
    """旧单步直传（视频封面等指定 object_key 场景）；连接超时重试 + STS 过期自动刷新"""
    image_path = Path(image_path)
    width, height = _get_image_dimensions(image_path)
    timestamp = current_timestamp_ms()
    guid = random_guid_compact()
    if not object_key:
        object_key = (
            f"/app/2026/community/{context.user_id}_modelMI8UDmodel_byte114995byte_"
            f"{guid}_{timestamp}_du_android_w{width}_h{height}.png"
        )

    from email.utils import formatdate
    # 本地 OSS V1 签名（对齐视频上传逻辑，不再依赖第三方签名服务）
    bucket_name = oss_info.get("bucketName") or "dewu-image"
    oss_host = oss_info.get("customEndpoint") or oss_info.get("ossHost") or "https://dewu-image.oss-cn-shanghai.aliyuncs.com"
    if oss_host and not oss_host.startswith(("http://", "https://")):
        oss_host = "https://" + oss_host.rstrip("/")  # 服务器返回裸域名，补 scheme
    access_key_id = oss_info.get("AccessKeyId", "")
    access_key_secret = oss_info.get("AccessKeySecret", "")
    security_token = oss_info.get("SecurityToken", "")
    if not (access_key_id and access_key_secret and security_token):
        raise RuntimeError("图片OSS信息缺少STS凭证")
    ext = (image_path.suffix or "").lower()
    content_type = "image/jpeg"
    if ext in (".png",):
        content_type = "image/png"
    elif ext in (".webp",):
        content_type = "image/webp"
    elif ext in (".gif",):
        content_type = "image/gif"

    for attempt in range(2):
        date_str = formatdate(usegmt=True)
        # object_key 带前导 /，资源路径 = 桶名 + object_key
        canonicalized_resource = f"/{bucket_name}{object_key}"
        oss_headers = {"x-oss-security-token": security_token}
        signature = _oss_v1_sign("PUT", content_type, date_str, canonicalized_resource, access_key_secret, oss_headers)
        upload_url = f"{oss_host}{object_key}"
        upload_headers = {
            'Authorization': f"OSS {access_key_id}:{signature}",
            'x-oss-security-token': security_token,
            'Date': date_str,
            'Content-Type': content_type,
        }

        # 上传图片，支持连接超时自动重试
        upload_response = None
        for upload_attempt in range(3):
            try:
                with image_path.open("rb") as file_handle:
                    upload_response = http_call("put", 
                        upload_url,
                        data=file_handle,
                        headers=upload_headers,
                        timeout=timeout,
                    )
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
                if upload_attempt < 2:
                    wait_time = 5 * (upload_attempt + 1)
                    log(f'  上传连接超时（第{upload_attempt+1}次），等待{wait_time}秒后重试...')
                    time.sleep(wait_time)
                else:
                    raise RuntimeError(f"OSS upload failed after 3 retries: {e}")

        if upload_response and upload_response.status_code == 200:
            return IMAGE_CDN + object_key

        if attempt == 0:
            if _is_oss_security_token_expired(upload_response.status_code, upload_response.text):
                log("OSS临时凭证已过期，正在自动刷新并重试当前图片")
                refreshed_oss_info = get_oss_info(context)
                if not isinstance(refreshed_oss_info, dict):
                    raise RuntimeError("OSS refresh response is invalid")
                oss_info.clear()
                oss_info.update(refreshed_oss_info)
                continue  # 刷新后自动重试，而不是直接报错
            raise RuntimeError(
                f"OSS upload failed: HTTP {upload_response.status_code} {upload_response.text[:300]}"
            )
        raise RuntimeError("OSS upload failed after refreshing security token")


def upload_video_cover(
    cover_path: str,
    image_oss_info: dict,
    context: DewuContext,
    log=lambda _msg: None,
) -> str:
    """
    上传视频封面图到图片桶的临时路径（对齐真实App：/app/temp/2026/community/...jpg）
    返回封面URL；失败返回空字符串
    """
    try:
        cover_path = Path(cover_path)
        if not cover_path.exists():
            log(f"  封面图不存在: {cover_path}")
            return ""
        width, height = _get_image_dimensions(cover_path)
        file_size = cover_path.stat().st_size
        timestamp = current_timestamp_ms()
        guid = random_guid_compact()
        object_key = (
            f"/app/temp/2026/community/{context.user_id}_model{DEVICE_TRAIT}model_byte{file_size}byte_"
            f"{guid}_{timestamp}_du_android_w{width}_h{height}.jpg"
        )
        return upload_image_to_oss(str(cover_path), image_oss_info, context, log=log, object_key=object_key)
    except Exception as e:
        log(f"  封面图上传异常: {e}")
        return ""


def upload_video_to_oss(
    video_path: str,
    oss_info: dict,
    context: DewuContext,
    timeout: int = 300,
    log=lambda _msg: None,
) -> dict:
    """
    上传视频到OSS，返回视频信息（URL、时长、分辨率等）
    """
    video_path = Path(video_path)
    file_size = video_path.stat().st_size
    timestamp = current_timestamp_ms()
    guid = random_guid_compact()
    
    # 视频object_key，和图片格式保持一致，只是后缀改成.mp4
    object_key = (
        f"/app/2026/community/{context.user_id}_modelMI8UDmodel_byte114995byte_"
        f"{guid}_{timestamp}_du_android.mp4"
    )
    
    log(f'  开始上传视频: {video_path.name} ({file_size/1024/1024:.1f}MB)')
    
    for attempt in range(2):
        # 调用第三方签名服务
        sign_response = http_call("post", 
            OSS_SIGN_URL,
            params={"object_key": object_key},
            json=oss_info,
            headers={
                'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
                'Content-Type': "application/json",
                'Accept': "application/json",
            },
            timeout=60,
        )
        sign_response.raise_for_status()
        sign_data = sign_response.json().get("data", {})
        upload_url = sign_data.get("upload_url")
        if not upload_url:
            raise RuntimeError("OSS sign response missing upload_url")

        upload_headers = {
            'Authorization': str(sign_data.get("authorization", "")),
            'x-oss-security-token': str(sign_data.get("x-oss-security-token", "")),
            'Date': str(sign_data.get("date", "")),
        }

        # 上传视频，支持连接超时自动重试
        upload_response = None
        for upload_attempt in range(3):
            try:
                with video_path.open("rb") as file_handle:
                    upload_response = http_call("put", 
                        upload_url,
                        data=file_handle,
                        headers=upload_headers,
                        timeout=timeout,
                    )
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
                if upload_attempt < 2:
                    wait_time = 10 * (upload_attempt + 1)
                    log(f'  视频上传连接超时（第{upload_attempt+1}次），等待{wait_time}秒后重试...')
                    time.sleep(wait_time)
                else:
                    raise RuntimeError(f"Video OSS upload failed after 3 retries: {e}")

        if upload_response and upload_response.status_code == 200:
            video_url = IMAGE_CDN + object_key
            log(f'  视频上传成功: {video_url}')
            
            # 尝试获取视频信息（时长、分辨率）
            video_info = {
                'url': video_url,
                'size': file_size,
                'duration': 0,
                'width': 0,
                'height': 0,
            }
            
            # 使用内置ffmpeg获取视频信息
            probe_info = _get_video_info(str(video_path))
            video_info['duration'] = probe_info.get('duration', 0)
            video_info['width'] = probe_info.get('width', 0)
            video_info['height'] = probe_info.get('height', 0)
            
            return video_info

        if attempt == 0:
            if _is_oss_security_token_expired(upload_response.status_code, upload_response.text):
                log("OSS临时凭证已过期，正在自动刷新并重试当前视频")
                refreshed_oss_info = get_oss_info(context)
                if not isinstance(refreshed_oss_info, dict):
                    raise RuntimeError("OSS refresh response is invalid")
                oss_info.clear()
                oss_info.update(refreshed_oss_info)
                continue  # 刷新后自动重试，而不是直接报错
            raise RuntimeError(
                f"OSS upload failed: HTTP {upload_response.status_code} {upload_response.text[:300]}"
            )
        raise RuntimeError("OSS upload failed after refreshing security token")


def get_video_oss_info(context: DewuContext, timeout: int = 20) -> dict:
    """
    获取视频上传OSS信息（独立视频桶 dw-video）
    真实App调用: get-oss-info?cdnType=1&scene=content-publish-video
    返回 data 字段包含 STS 凭证 + 桶信息
    """
    timestamp = current_timestamp_ms()
    new_sign = build_get_new_sign({'cdnType': "1", 'scene': "content-publish-video"}, timestamp,
                                  uuid_value=_session_uuid(context.token))
    url = (
        "https://app.dewu.com/sns-conf/v1/config/get-oss-info"
        f"?cdnType=1&scene=content-publish-video&newSign={new_sign}"
    )
    response = http_call("get", url, headers=dewu_auth_headers(context, timestamp), timeout=timeout)
    _capture_waf_cookie(response)
    response.raise_for_status()
    data = response.json()
    # 兼容 {code,data:{...}} 与直接 data 两种返回
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if isinstance(data, dict) and data.get("AccessKeyId"):
        return data
    raise RuntimeError(f"get video oss-info failed: {str(data)[:300]}")


def build_video_object_key(
    user_id: str,
    file_size: int,
    duration_ms: int,
    width: int,
    height: int,
    bucket_dir: str = "app/sns-og/2026/video/",
) -> str:
    """构造视频对象key，格式对齐真实App：
    <userid>_byte<字节>_dur<毫秒>_<guid>_<时间戳>_du_android_w<宽>h<高>.mp4
    """
    timestamp = current_timestamp_ms()
    guid = random_guid_compact()
    filename = (
        f"{user_id}_byte{file_size}_dur{duration_ms}_{guid}_{timestamp}"
        f"_du_android_w{width}h{height}.mp4"
    )
    return (bucket_dir + filename).lstrip("/")


def _oss_v1_sign(method, content_type, date, canonicalized_resource, access_key_secret, oss_headers=None):
    """
    OSS V1签名（对齐阿里云官方 oss2 SDK）
    StringToSign = VERB\\n Content-MD5\\n Content-Type\\n Date\\n CanonicalizedOSSHeaders\\n CanonicalizedResource
    CanonicalizedOSSHeaders 包含所有 x-oss-* 头（小写、去空格、按名排序，每条以\\n结尾）
    """
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hm
    canonicalized_headers = ''
    if oss_headers:
        for k in sorted(oss_headers.keys()):
            kl = k.lower()
            if kl.startswith('x-oss-'):
                canonicalized_headers += f'{kl}:{str(oss_headers[k]).strip()}\n'
    string_to_sign = f"{method}\n\n{content_type}\n{date}\n{canonicalized_headers}{canonicalized_resource}"
    digest = _hm.new(access_key_secret.encode("utf-8"), string_to_sign.encode("utf-8"), _hl.sha1).digest()
    return _b64.b64encode(digest).decode("ascii")


def upload_video_to_dewu_oss(
    video_path,
    video_oss_info: dict,
    context: DewuContext,
    log=lambda _msg: None,
    timeout: int = 600,
) -> dict:
    """
    直传视频到得物视频桶 dw-video（使用 STS 临时凭证 + OSS V1 签名）
    返回 {'url': 视频CDN地址, 'size':..., 'duration':..., 'width':..., 'height':...}
    """
    import datetime as _dt
    from email.utils import formatdate

    video_path = Path(video_path)
    file_size = video_path.stat().st_size

    # 读取视频信息（时长毫秒、分辨率）
    probe = _get_video_info(str(video_path))
    duration_ms = int((probe.get("duration") or 0) * 1000)
    width = probe.get("width") or 0
    height = probe.get("height") or 0
    if not duration_ms or not width or not height:
        raise RuntimeError(f"无法读取视频信息(时长/分辨率): {probe}")

    bucket_dir = video_oss_info.get("bucketDir") or "app/sns-og/2026/video/"
    oss_host = video_oss_info.get("ossHost") or "https://dw-video.oss-cn-shanghai.aliyuncs.com"
    if oss_host and not oss_host.startswith(("http://", "https://")):
        oss_host = "https://" + oss_host.rstrip("/")  # 服务器返回裸域名，补 scheme
    cdn_host = video_oss_info.get("cdnHost") or "https://videocdn.poizon.com"
    access_key_id = video_oss_info.get("AccessKeyId", "")
    access_key_secret = video_oss_info.get("AccessKeySecret", "")
    security_token = video_oss_info.get("SecurityToken", "")
    bucket_name = video_oss_info.get("bucketName") or "dw-video"
    if not (access_key_id and access_key_secret and security_token):
        raise RuntimeError("视频OSS信息缺少STS凭证")

    object_key = build_video_object_key(
        context.user_id, file_size, duration_ms, width, height, bucket_dir
    )
    upload_url = f"{oss_host}/{object_key}"
    log(f"  视频上传地址: {upload_url[:120]}...")

    date_str = formatdate(usegmt=True)
    # 对齐阿里云官方 oss2 SDK：虚拟主机风格下签名资源含桶名
    canonicalized_resource = f"/{bucket_name}/{object_key}"
    oss_headers = {"x-oss-security-token": security_token}
    signature = _oss_v1_sign("PUT", "video/mp4", date_str, canonicalized_resource, access_key_secret, oss_headers)

    headers = {
        "Authorization": f"OSS {access_key_id}:{signature}",
        "x-oss-security-token": security_token,
        "Date": date_str,
        "Content-Type": "video/mp4",
    }

    last_exc = None
    for attempt in range(3):
        try:
            with video_path.open("rb") as fh:
                resp = http_call("put", upload_url, data=fh, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                video_url = f"{cdn_host}/{object_key}"
                log(f"  视频上传成功: {video_url[:120]}...")
                return {
                    "url": video_url,
                    "size": file_size,
                    "duration": probe.get("duration") or 0,
                    "width": width,
                    "height": height,
                }
            log(f"  视频上传失败 HTTP {resp.status_code}: {resp.text[:200]}")
            if resp.status_code == 403 and "SecurityTokenExpired" in resp.text:
                # 仅当临时凭证过期时刷新重试
                refreshed = get_video_oss_info(context)
                for k, v in refreshed.items():
                    video_oss_info[k] = v
                access_key_id = video_oss_info.get("AccessKeyId", "")
                access_key_secret = video_oss_info.get("AccessKeySecret", "")
                security_token = video_oss_info.get("SecurityToken", "")
                oss_headers = {"x-oss-security-token": security_token}
                signature = _oss_v1_sign("PUT", "video/mp4", date_str, canonicalized_resource, access_key_secret, oss_headers)
                headers["Authorization"] = f"OSS {access_key_id}:{signature}"
                headers["x-oss-security-token"] = security_token
                continue
            raise RuntimeError(f"视频上传失败: HTTP {resp.status_code} {resp.text[:200]}")
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout) as e:
            last_exc = e
            wait = 10 * (attempt + 1)
            log(f"  视频上传连接异常（第{attempt + 1}次），{wait}秒后重试...")
            import time as _time
            _time.sleep(wait)
    raise RuntimeError(f"视频上传失败 after 3 retries: {last_exc}")


def _get_ffmpeg_path() -> str:
    """获取ffmpeg可执行文件路径，优先使用imageio-ffmpeg内置的ffmpeg"""
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError:
        pass
    # 尝试使用系统PATH中的ffmpeg
    return "ffmpeg"


def _get_video_info(video_path: str) -> dict:
    """使用ffmpeg获取视频信息（时长、分辨率）"""
    video_info = {'duration': 0, 'width': 0, 'height': 0}
    try:
        import subprocess
        ffmpeg_path = _get_ffmpeg_path()
        # 使用ffmpeg获取视频信息
        result = subprocess.run(
            [ffmpeg_path, '-i', str(video_path)],
            capture_output=True, text=True, timeout=10
        )
        # 从stderr中解析视频信息
        output = result.stderr
        import re
        # 匹配时长：Duration: 00:00:05.00
        duration_match = re.search(r'Duration:\s+(\d+):(\d+):([\d.]+)', output)
        if duration_match:
            hours = int(duration_match.group(1))
            minutes = int(duration_match.group(2))
            seconds = float(duration_match.group(3))
            video_info['duration'] = int(hours * 3600 + minutes * 60 + seconds)
        # 匹配分辨率：1920x1080
        resolution_match = re.search(r'(\d{3,4})x(\d{3,4})', output)
        if resolution_match:
            video_info['width'] = int(resolution_match.group(1))
            video_info['height'] = int(resolution_match.group(2))
    except Exception:
        pass
    return video_info

def extract_video_frame(video_path: str, output_path: str = None, frame_time: float = 1.0) -> str:
    """
    从视频中提取第一帧作为封面图
    使用imageio-ffmpeg内置的ffmpeg，无需单独安装
    """
    video_path = Path(video_path)
    if output_path is None:
        output_path = video_path.parent / f"{video_path.stem}_frame.jpg"
    output_path = Path(output_path)

    try:
        import subprocess
        ffmpeg_path = _get_ffmpeg_path()
        result = subprocess.run(
            [ffmpeg_path, '-y', '-i', str(video_path), '-ss', str(frame_time), 
             '-vframes', '1', '-q:v', '2', str(output_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and output_path.exists():
            return str(output_path)
    except Exception:
        pass
    
    return ""


def build_video_band_info(video_info: dict) -> str:
    """构建视频带宽信息"""
    import json as json_mod
    band_info = {
        'duration': video_info.get('duration', 0),
        'width': video_info.get('width', 0),
        'height': video_info.get('height', 0),
        'size': video_info.get('size', 0),
    }
    return json_mod.dumps(band_info, ensure_ascii=False)


def build_images_payload(image_urls: list) -> str:
    """构建发布动态的图片参数（对齐 6.0.0 抓包：仅首项带 bandInfo.edit，全项含 isMuted/mediaExtraInfo 等字段）"""
    items = []
    for index, image_url in enumerate(image_urls):
        item = {
            'isMuted': False,
            'isVote': False,
            'mediaExtraInfo': '{"isHdr":0}',
            'pictureBeautyId': [],
            'pictureTemplate': 0,
            'realShot': False,
            'source': 0,
            'tagPosition': [],
            'url': image_url,
        }
        if index == 0:
            # 抓包实证：仅首项带 bandInfo:{"edit":[]}
            item = {'bandInfo': {'edit': []}, **item}
        items.append(item)
    return json.dumps(items, ensure_ascii=False)


def build_product_content_tags(product_ids: list) -> str:
    """构建关联商品标签

    product_ids 支持两种格式（向后兼容）：
    - "productId:propertyId"（规格级）：对齐 6.0 真实发布抓包——id=SPU、extraId=规格ID、tagSource=2、无 extraInfo
    - "productId"（纯 SPU）：沿用旧结构 extraId="0" + tagSource=0 + extraInfo
    """
    tags = []
    for product_id in product_ids:
        product_id = str(product_id).strip()
        if ':' in product_id:
            pid, _, prop_id = product_id.partition(':')
            tags.append({
                'dir': 0,
                'endFrame': 0,
                'extraId': prop_id,
                'id': pid,
                'sourceType': "4",
                'startFrame': 0,
                'tagSource': 2,
                'type': "3",
                'width': 0,
                'x': 0,
                'y': 0,
            })
        else:
            tags.append({
                'dir': 0,
                'extraId': "0",
                'extraInfo': {'goodsId': "0", 'goodsType': "0", 'show': 0},
                'id': product_id,
                'sourceType': "4",
                'tagSource': 0,
                'type': "3",
                'width': 0,
                'x': 0,
                'y': 0,
            })
    return json.dumps(tags, ensure_ascii=False)


def search_topics(keyword: str, context: DewuContext, timeout: int = 20) -> list:
    """关键词模糊搜索话题列表（search-tags 接口，响应为明文 JSON）

    返回精简字段列表：tagName/tagId/containsNum(笔记数)/hotNumber(热度)/thumb(封面)
    """
    keyword = keyword.lstrip("#＃").strip()
    if not keyword:
        return []
    ts = current_timestamp_ms()
    new_sign = build_post_new_sign({"keyword": keyword}, ts,
                                   uuid_value=_session_uuid(context.token))
    response = http_call("post",
        f"https://app.dewu.com/sns-cnt-tag/v1/tag/search-tags?newSign={new_sign}",
        data={"keyword": keyword},
        headers=dewu_auth_headers(context, ts),
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    items = []
    for item in data.get("data", {}).get("list", []) or []:
        items.append({
            'tagName': str(item.get('tagName', '')),
            'tagId': str(item.get('tagId', '')),
            'containsNum': str(item.get('containsNum', '0')),
            'hotNumber': item.get('hotNumber', 0),
            'thumb': str(item.get('thumb', '')),
        })
    return items


def search_product(keyword: str, context: DewuContext, limit: int = 20,
                   timeout: int = 20) -> list:
    """商品搜索（发布页关联商品用的 list-product 接口，6.0 抓包实证）

    keyword 支持货号（如 HQ6457-001）或标题关键词；纯数字 productId 无法命中（得物搜索不索引）。
    旧 sign 参数可不带（服务端只校验 newSign，盲测实证）。
    返回规格级记录列表（不去重）：同一 productId 每个规格（propertyId）一条记录，
    发布挂链接精确到规格就是靠 (productId, propertyId) 对——对应 contentTags 的 (id, extraId)。
    """
    keyword = keyword.strip()
    if not keyword:
        return []
    ts = current_timestamp_ms()
    query = {'title': keyword, 'page': "1", 'ignore_ids': "", 'limit': str(limit),
             'source': "1", 'abRelationGoods': "1"}
    new_sign = build_get_new_sign(query, ts, uuid_value=_session_uuid(context.token),
                                  login_token=context.login_token)
    url = ("https://app.dewu.com/sns-cnt-tag/v1/search/list-product?"
           + urllib.parse.urlencode({**query, 'newSign': new_sign}))
    response = http_call("get", url, headers=dewu_auth_headers(context, ts), timeout=timeout)
    response.raise_for_status()
    data = response.json()
    items = []
    for item in data.get("data", {}).get("list", []) or []:
        pid = str(item.get('productId', '') or '')
        if not pid:
            continue
        items.append({
            'productId': pid,
            'propertyId': str(item.get('propertyId', '') or ''),
            'propertyTitle': str(item.get('propertyTitle', '') or ''),
            'title': str(item.get('title', '')),
            'articleNumber': str(item.get('articleNumber', '')),
            'brandName': str(item.get('brandName', '')),
            'logoUrl': str(item.get('logoUrl', '')),
        })
        if len(items) >= 20:
            break
    return items


def pick_hot_topics(keywords: list, context: DewuContext, top_n: int = 10,
                    pick: int = 4, exclude: tuple = (), timeout: int = 20) -> list:
    """按关键词搜索话题榜：聚合去重 → 按热度降序取前 top_n → 随机抽 pick 个

    exclude: 需排除的话题名（如用户手动填写的），避免重复。
    返回 [{'tagName','tagId','containsNum','hotNumber'}]，任一关键词失败不影响其余。
    """
    exclude_names = {str(e).strip().lstrip('#＃').strip() for e in exclude if str(e).strip()}
    merged = {}
    for kw in keywords:
        kw = str(kw).strip().lstrip('#＃')
        if not kw:
            continue
        try:
            items = search_topics(kw, context, timeout=timeout)
            log(f'  话题榜[{kw}]: {len(items)} 条')
        except Exception as e:
            log(f'  话题榜[{kw}]搜索失败: {e}')
            items = []
        for it in items:
            tid = it.get('tagId', '')
            if tid and tid not in merged and it.get('tagName', '') not in exclude_names:
                merged[tid] = it
        time.sleep(random.uniform(0.5, 1.5))  # 关键词间抖动，防限流
    ranked = sorted(merged.values(), key=lambda x: x.get('hotNumber', 0), reverse=True)
    top = ranked[:top_n]
    picked = random.sample(top, min(max(pick, 0), len(top)))
    log(f'  话题榜聚合 {len(merged)} 条，取热度前{len(top)}，随机抽 {len(picked)} 个: '
        + '、'.join(p['tagName'] for p in picked))
    return picked


def search_topic_id(topic: str, context: DewuContext, timeout: int = 20) -> str:
    """搜索话题ID"""
    topic = topic.lstrip("#＃").strip()
    ts = current_timestamp_ms()
    new_sign = build_post_new_sign({"keyword": topic}, ts,
                                   uuid_value=_session_uuid(context.token))
    response = http_call("post", 
        f"https://app.dewu.com/sns-cnt-tag/v1/tag/search-tags?newSign={new_sign}",
        data={"keyword": topic},
        headers=dewu_auth_headers(context, ts),
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    for item in data.get("data", {}).get("list", []) or []:
        if str(item.get("tagName", "")) == topic:
            return str(item.get("tagId", ""))
    return ""


def build_topic_tags(topics_text: str, context: DewuContext, timeout: int = 20) -> str:
    """构建话题标签"""
    import re
    topic_tags = []
    # 按 # 或空白拆分话题（兼容空格分隔的"#A #B #C"和换行分隔）
    topics = [t.strip().lstrip("#＃").strip()
              for t in re.split(r"[#＃\s]+", topics_text) if t.strip()]
    for position, topic in enumerate(topics):
        topic_id = search_topic_id(topic, context, timeout=timeout)
        topic_tags.append({
            'id': int(topic_id) if topic_id.isdigit() else topic_id,
            'name': topic,
            'position': position,
            'step': len(topic),
            'type': 5,
        })
    return json.dumps(topic_tags, ensure_ascii=False)


def trend_save_check(
    *,
    context: DewuContext,
    title: str,
    content: str,
    images_payload: str,
    topic_tags: str,
    tag_id: str = "",
    pic: str = "0",
    word: str = "0",
    content_tags: str = "[]",
    timeout: int = 20,
) -> None:
    """发布前预检（trend-save-check，表单对齐 6.0.0 抓包）；result=false 抛 RuntimeError 阻断发布"""
    payload = {
        'trendId': "",
        'type': "0",
        'tagId': tag_id,
        'title': title,
        'content': content,
        'city': "",
        'lng': "0.0",
        'lat': "0.0",
        'videoUrl': "",
        'atUserIds': "",
        'atUserList': "[]",
        'images': images_payload,
        'template': "",
        'videoFrame': "",
        'videoBandInfo': "",
        'videoPosition': "",
        'sharpInfo': topic_tags,
        'priori': "0",
        'newStruct': "1",
        'videoBeautyId': "",
        'pic': pic,
        'word': word,
        'orderId': "",
        'userShowStatus': "0",
        'extraData': '{"v536RemianTask":"0"}',
        'aiAvatar': "",
        'actExtraInfo': "",
        'checkField': '["freeOrder","topic"]',
        'freeOrder': "",
        'contentTags': content_tags,
    }
    ts = current_timestamp_ms()
    new_sign = build_post_new_sign(payload, ts,
                                   uuid_value=_session_uuid(context.token))
    response = http_call("post",
        f"https://app.dewu.com/sns-cnt-center/v1/content/trend-save-check?newSign={new_sign}",
        data=payload,
        headers=dewu_auth_headers(context, ts),
        timeout=timeout,
    )
    _capture_waf_cookie(response)
    response.raise_for_status()
    data = response.json()
    data_field = data.get("data") if isinstance(data.get("data"), dict) else {}
    if data_field.get("result") is not True:
        msg = data_field.get("msg") or data.get("msg") or ""
        raise RuntimeError(msg or "result=false")


def publish_trend(
    *,
    title: str,
    content: str,
    topics: str = "",
    images_payload: str = "",
    context: DewuContext,
    product_content_tags: str = "",
    friend: str = "",
    timeout: int = 30,
    retries: int = 3,
    video_url: str = "",
    video_frame: str = "",
    video_band_info: str = "",
) -> PublishResult:
    """
    发布动态
    """
    # 组装文案内容（6.0.0 抓包实证：正文后直接接话题、话题间单空格、末尾一个空格，无换行）
    normalized_topics = [line.strip().lstrip("#＃").strip()
                         for line in topics.replace("\r\n", "\n").split("\n") if line.strip()]
    topic_content = " ".join(f"#{topic}" for topic in normalized_topics)
    if topic_content:
        topic_content += " "
    friend_content = f"@{friend} " if friend else ""
    final_content = content + friend_content + topic_content

    # 构建话题标签
    topic_tags = ""
    if normalized_topics:
        try:
            topic_tags = build_topic_tags(topics, context, timeout=timeout)
        except Exception:
            topic_tags = ""

    # 判断是图文还是视频
    is_video = bool(video_url)
    
    # 视频发布时，videoBandInfo需要是JSON对象，而不是JSON字符串
    video_band_obj = {}
    if is_video and video_band_info:
        try:
            import json as json_mod
            video_band_obj = json_mod.loads(video_band_info)
        except Exception:
            video_band_obj = {}
    
    if is_video:
        # 视频发布：完全对齐真实App请求体（7.har抓包，明文form，无加密）
        frame_obj = {
            "coverTpl": 0, "coverType": 2, "fontId": "0", "recourceIds": [],
            "startFrame": 0, "stopFrame": 2000, "text": "", "texts": [], "videoUrl": "",
        }
        images_arr = []
        if video_frame:
            # 封面图放入images数组（对齐真机格式）
            images_arr.append({"pictureTemplate": 0, "realShot": False, "url": video_frame})
        payload = {
            'type': "1",
            'videoUrl': video_url,
            'content': final_content,
            'images': json.dumps(images_arr, ensure_ascii=False),
            'atUserList': "[]",
            'products': "",
            'entryId': "0",
            'voteTitles': "null",
            'city': "",
            'lng': "0.0",
            'lat': "0.0",
            'from': "0",
            'tagId': "",
            'clockInId': "",
            'videoPosition': "[]",
            'title': title or "",
            'videoBandInfo': json.dumps(video_band_obj, ensure_ascii=False) if video_band_obj else (video_band_info or ""),
            'isWash': "0",
            'orderId': "",
            'videoFrame': json.dumps(frame_obj, ensure_ascii=False),
            'template': "",
            'sharpInfo': topic_tags,
            'priori': "0",
            'newStruct': "1",
            'commercialBrand': "",
            'isOrderShare': "0",
            'videoBeautyId': "[]",
            'pic': "0",
            'word': "46",
            'isHotCommodity': "0",
            'entrySource': "0",
            'isAurora': "0",
            'userShowStatus': "0",
            'contentTags': product_content_tags,
            'isPanoramicVideo': "0",
            'extraData': '{"v536RemianTask":"0"}',
            'actExtraInfo': "",
            'newtouch': "1",
        }
    else:
        # 图文发布：完全对齐 6.0.0 抓包表单（无 trendId，tagId=主话题id，键序照抄）
        tag_id = ""
        if topic_tags and topic_tags != "[]":
            try:
                tag_id = str(json.loads(topic_tags)[0].get("id", ""))
            except Exception:
                tag_id = ""
        try:
            pic_count = len(json.loads(images_payload)) if images_payload else 0
        except Exception:
            pic_count = 0
        pic_str = str(pic_count)
        # word 实证：len(title)+len(content)-2*话题数（不计#与空格）→ 抓包 14+107-10=111
        word_str = str(len(title or "") + len(final_content) - 2 * len(normalized_topics))
        content_tags_value = product_content_tags or "[]"
        # 发布前预检：result=false 阻断发布
        try:
            trend_save_check(
                context=context,
                title=title or "",
                content=final_content,
                images_payload=images_payload,
                topic_tags=topic_tags,
                tag_id=tag_id,
                pic=pic_str,
                word=word_str,
                content_tags=content_tags_value,
                timeout=timeout,
            )
        except Exception as exc:
            return PublishResult(
                success=False,
                response_text="",
                message=f"发布预检未通过: {exc}",
            )
        payload = {
            'type': "0",
            'videoUrl': "",
            'content': final_content,
            'images': images_payload,
            'atUserList': "[]",
            'products': "",
            'entryId': "0",
            'voteTitles': "null",
            'city': "",
            'lng': "0.0",
            'lat': "0.0",
            'from': "0",
            'tagId': tag_id,
            'title': title or "",
            'isWash': "0",
            'orderId': "",
            'videoBandInfo': "",
            'videoFrame': "",
            'template': "",
            'videoMd5': "",
            'sharpInfo': topic_tags,
            'priori': "0",
            'newStruct': "1",
            'commercialBrand': "",
            'isOrderShare': "0",
            'videoBeautyId': "",
            'pic': pic_str,
            'word': word_str,
            'isHotCommodity': "0",
            'entrySource': "1",
            'isAurora': "0",
            'userShowStatus': "0",
            'contentTags': content_tags_value,
            'isPanoramicVideo': "0",
            'extraData': '{"v536RemianTask":"0"}',
            'actExtraInfo': "",
            'newtouch': "1",
            'freeOrder': "",
            'aiDetectionTaskId': "0",
        }

    last_text = ""
    fail_message = ""
    for attempt_no in range(1, retries + 1):
        try:
            ts = current_timestamp_ms()
            new_sign = build_post_new_sign(payload, ts,
                                           uuid_value=_session_uuid(context.token))
            response = http_call("post", 
                f"https://app.dewu.com/sns-cnt-center/v1/content/trend-publish?newSign={new_sign}",
                data=payload,
                headers=dewu_auth_headers(context, ts),
                timeout=timeout,
                allow_redirects=True,
            )
            _capture_waf_cookie(response)
            response.raise_for_status()  # 非2xx会抛HTTPError
            parsed_text = urllib.parse.unquote(response.text)
        except requests.exceptions.ConnectTimeout as exc:
            # 连接都没建立 → 请求确定未送达服务端，可安全重试
            last_text = ""
            fail_message = f"发布连接失败（第{attempt_no}/{retries}次）: {exc}"
        except requests.exceptions.ReadTimeout as exc:
            # 请求已发出、响应未收到：服务端可能已建帖。trend-publish 非幂等（无幂等键），
            # 重发=重复发布 → 立即终止，让用户先到 App 确认
            return PublishResult(
                success=False,
                response_text="",
                message="发布请求超时且结果未知（服务端可能已发布成功）。请先到得物App确认是否已发出，"
                        "确认未发出再重新发布，不要直接重试",
            )
        except requests.exceptions.ConnectionError as exc:
            # 含读响应阶段断连（BrokenPipe/RemoteDisconnected）：请求可能已到服务端 → 不重试
            return PublishResult(
                success=False,
                response_text="",
                message=f"发布连接中断且结果未知（服务端可能已发布成功），请先到得物App确认后再操作: {exc}",
            )
        except requests.exceptions.RequestException as exc:
            # 其余异常（如参数构造问题）：请求大概率未送达 → 可重试
            last_text = ""
            fail_message = f"发布请求失败（第{attempt_no}/{retries}次）: {exc}"
        else:
            last_text = parsed_text
            details = _parse_publish_response_details(last_text)
            resp_code = str(_extract_json_value(last_text, "code") or "")
            if resp_code in ("200", "0"):
                # 外层 code=200/0 即服务端确认发布成功。data 加密串里的 contentId
                # 依赖 heracles 解密；2026-10 起服务端新变体（sks 如 "1,1,6"）在加密
                # 层内叠 zlib 压缩，引擎已自动解压（_heracles_engine），contentId
                # 新旧变体均可解出。成功判定仍以 code=200 为准，不依赖 contentId
                # 解密成败（误判失败会导致上层重发/用户手动重发 → 同图同文重复发布）
                return PublishResult(
                    success=True,
                    response_text=last_text,
                    message=_extract_json_value(last_text, "msg") or "发布成功",
                    http_status=200,
                    content_id=details.get("content_id", ""),
                    article_url=details.get("article_url", ""),
                )
            resp_msg = _extract_json_value(last_text, "msg") or _plain_fail_msg(last_text)
            if resp_code:
                # 服务端明确拒绝（code 非 200/0）→ 未建帖，可安全重试
                fail_message = f"服务端明确拒绝（code={resp_code}，第{attempt_no}/{retries}次）: {resp_msg}"
            else:
                # HTTP 200 但响应里连 code 都解析不出（含糊响应，疑似已建帖）：
                # 重发可能重复发布 → 不重试，让用户先到 App 确认
                return PublishResult(
                    success=False,
                    response_text=last_text,
                    message=f"发布响应无法确认结果（不自动重试以防重复发布）: "
                            f"{resp_msg or _publish_response_diagnostic(last_text)}",
                )
        if attempt_no < retries:
            time.sleep(2 + attempt_no)  # 失败后递增退避再重试

    return PublishResult(
        success=False,
        response_text=last_text,
        message=fail_message or (_extract_json_value(last_text, "msg") or _plain_fail_msg(last_text)),
    )


# ==================== 辅助函数 ====================
def _get_image_dimensions(path: Path) -> tuple:
    """获取图片尺寸"""
    try:
        from PIL import Image
        with Image.open(path) as image:
            width, height = image.size
            return (width or 800, height or 800)
    except ImportError:
        return (800, 800)
    except Exception:
        return (800, 800)


def _is_oss_security_token_expired(status_code: int, response_text: str) -> bool:
    """检查OSS安全令牌是否过期"""
    if status_code != 403:
        return False
    normalized = response_text.lower()
    return ("securitytokenexpired" in normalized) or (
        ("security token" in normalized) and ("expired" in normalized)
    )


def _extract_response_message(text: str) -> str:
    """提取响应消息"""
    code = _extract_json_value(text, "code")
    status = _extract_json_value(text, "status")
    if code or status:
        return f'code={code or "-"}, status={status or "-"}'
    return _extract_tag(text, "msg") or text[:300]


def _extract_tag(text: str, tag: str) -> str:
    """从XML-like格式中提取标签"""
    start = text.find(f"<{tag}>")
    if start == -1:
        return ""
    start += len(f"<{tag}>")
    end = text.find("<", start)
    if end == -1:
        return ""
    return text[start:end].strip()


def _extract_json_value(text: str, key: str) -> str:
    """从JSON中提取值"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ""
    else:
        value = _find_json_key(data, key)
        if value is None:
            return ""
        return str(value)


def _find_json_key(data: object, key: str) -> object:
    """递归查找JSON中的键"""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for value in data.values():
            found = _find_json_key(value, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_json_key(item, key)
            if found is not None:
                return found
    return None


def _decode_jwt_payload(token: str) -> dict:
    """解码JWT payload"""
    jwt = token.strip()
    if jwt.lower().startswith("bearer "):
        jwt = jwt[7:].strip()
    parts = jwt.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8")
        data = json.loads(decoded)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _parse_publish_response_details(response_text: str) -> dict:
    """解析发布响应详情"""
    try:
        payload = json.loads(response_text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    # data 为加密串（sks 加密响应）：heracles 解密提取 contentId（尽力而为）。
    # 新变体（sks 如 "1,1,6"）= 加密层内再叠 zlib，引擎已自动解压——
    # 2026-10-19 验证新旧变体均可解出 contentId；解密失败仅影响展示不影响成败判定
    if isinstance(data, str) and data:
        try:
            payload = json.loads(_heracles_decrypt(data))
            data = payload.get("data")
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    content = data.get("content")
    if not isinstance(content, dict):
        content = {}
    content_id_value = (
        content.get("contentId")
        or data.get("contentId")
        or _find_json_key(payload, "contentId")
        or ""
    )
    content_id = str(content_id_value).strip()
    return {
        'content_id': content_id,
        'article_url': f"https://m.dewu.com/rn-activity/community-share?trendId={content_id}" if content_id else "",
    }


def _publish_response_diagnostic(response_text: str) -> str:
    """发布响应诊断"""
    parts = []
    for key, label in (('code', 'code'), ('status', 'status'), ('msg', 'msg'), ('message', 'message')):
        value = _extract_json_value(response_text, key).strip()
        if value:
            if f"{label}={value}" not in parts:
                parts.append(f"{label}={value}")
    if parts:
        return "，".join(parts)
    return f"响应={response_text[:200]}"
