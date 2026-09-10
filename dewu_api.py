"""
得物蓝V自动发布工具 - 核心API模块
基于逆向分析得到的完整API调用逻辑
"""
import hashlib
import json
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

from modules.rizhi import log

# ==================== 常量 ====================
DEWU_AES_HEX_KEY = b'mobile0123456789'
DEWU_AES_BASE64_KEY = b'd245a0ba8d678a61'
# Mi6 edk（与 DEWU_AES_BASE64_KEY 配套，已验证签名通过）
DEFAULT_EDK = "6C7D61656D61352E6C7D7D7D616C356D3C3D386C303D303C3C6C393B316D3B2E6769616C35"

# 设备外壳：Huawei HMA-AL00 / Android 12（对齐"换设备只改外壳参数"方案）
USER_AGENT = "duapp/5.60.0(android;12)"
FULL_UA = "Dalvik/2.1.0 (Linux; U; Android 12; HMA-AL00 Build/HUAWEI.HMA-AL00-12)/duapp/5.60.0(android;12)"

# 设备指纹（华为新设备外壳 + 新随机设备ID，避免沿用被标记的旧指纹）
DEVICE_BRAND = "Huawei"
DEVICE_TRAIT = "HMA-AL00"
SHUMEII = "202609091261bd4b95e1cc089ddb4f3c1f6628445b9406cd1bb64291676ff3fc"

# 真机会话值（抓取自健康账号会话 6.har / 32132.har）
DEVICE_EDK = "6C7D61656D61352E6C7D7D7D616C356E6A3E396E3D393C30313A6D38383B382E6769616C35"
DEVICE_SK = "9UAHOuZNjmMregVpdl138oVAHwaRpLo0BmwGbgKPEbTkRjgPKtBLUVQOBJSQXaNsFcrxQ7Mn78abNlB8JocRBaLzww1y"
DEVICE_SKT = "adr1"
DEVICE_SKS = "0,adw2"
DEVICE_SS = "d19d521904b905b4ba2d48e8de886e5e"
DEVICE_DHW = "77a13c400ef7021546500527845aa4bfb30996bd0d56615dcc69"
DEVICE_LTK = "4tTwDJpVE5WYpx8DhEnnkvZzgtihcg"
DEVICE_ADI = "2vE8Btin7sDPTGDiVxWqfTDhFYBACUn7"
DEVICE_SKC = "6FXSz7s4Q4PzF9gORByIT"

UUID_FIXED = "e450d85844d139e3"
VERSION = "5.60.0"

# ==================== 设备身份随机化 ====================
# 实验实证（_ns99）：服务端风控锚点=shumeiid，随机新ID即放行不触发485滑块；
# 整套外壳（机型/UA/标识族）同步随机化，格式仿真，降低原真机指纹复用风险
import secrets as _secrets

_DEVICE_MODELS = [
    # (brand, trait, android_ver)  brand 大写用于 Build 串
    ("HUAWEI", "HMA-AL00", 12),
    ("XIAOMI", "M2012K11AC", 12),
    ("XIAOMI", "MI 9", 11),
    ("samsung", "SM-G9910", 13),
    ("OPPO", "PEYM00", 12),
    ("vivo", "V2218A", 13),
    ("HUAWEI", "NOH-AN00", 12),
    ("OnePlus", "LE2110", 13),
]

_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _rnd_str(n: int) -> str:
    return "".join(_secrets.choice(_B62) for _ in range(n))


def randomize_device() -> dict:
    """整套随机设备身份：机型外壳(UA/brand/trait) + 全部设备标识。返回当前值快照"""
    global USER_AGENT, FULL_UA, DEVICE_BRAND, DEVICE_TRAIT, SHUMEII
    global DEVICE_SK, DEVICE_LTK, DEVICE_ADI, DEVICE_SKC, UUID_FIXED
    brand, trait, av = _secrets.choice(_DEVICE_MODELS)
    DEVICE_BRAND = brand.capitalize()
    DEVICE_TRAIT = trait
    USER_AGENT = f"duapp/{VERSION}(android;{av})"
    FULL_UA = (f"Dalvik/2.1.0 (Linux; U; Android {av}; {trait} "
               f"Build/{brand}.{trait.replace(' ', '')}-{av})/duapp/{VERSION}(android;{av})")
    SHUMEII = _secrets.token_hex(32)                       # 数美设备ID（风控锚点，已实证随机即过）
    DEVICE_SK = _rnd_str(len(DEVICE_SK))
    DEVICE_LTK = _rnd_str(30)
    DEVICE_ADI = _rnd_str(32)
    DEVICE_SKC = _rnd_str(21)
    UUID_FIXED = _secrets.token_hex(8)                     # iaid
    return {
        'brand': DEVICE_BRAND, 'trait': DEVICE_TRAIT, 'android': av,
        'shumeiid': SHUMEII[:16] + "...", 'ua': USER_AGENT,
    }

# 数美sign（旧明文form sendCaptcha用，随body提交）
SIGN_FIXED = "7141a0b174c0282e3c7c93d999df751f"

# OSS签名服务（第三方）
OSS_SIGN_URL = "http://43.138.142.207:6668/auto_oss_v1_sign"

# 图片CDN
IMAGE_CDN = "https://image-cdn.poizon.com"


# ==================== 数据类 ====================
@dataclass
class DewuContext:
    """得物认证上下文"""
    token: str
    user_id: str
    edk: str = DEFAULT_EDK
    user_name: str = ""


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
    """发送验证码newSign（明文form路径）——通用规则的薄封装"""
    body = {'msgType': "0", 'typeId': "1", 'riskTypeId': "1",
            'mobile': encrypted_mobile, 'countryCode': "86", 'cipherParam': "mobile"}
    return build_post_new_sign(body, timestamp)


def build_login_new_sign(encrypted_mobile: str, captcha: str, timestamp: str) -> str:
    """验证码登录newSign（JSON body）——通用规则的薄封装"""
    body = {'cipherParam': "userName", 'code': captcha, 'countryCode': 86,
            'type': "code", 'userName': encrypted_mobile}
    return build_post_new_sign(body, timestamp)


# ==================== 请求头 ====================
def _init_headers(timestamp: str) -> dict:
    """client/init请求头"""
    return {
        'ltk': DEVICE_LTK,
        'app_build': "5.60.0.10",
        'ipvx': "14.212.23.140",
        'cookieToken': "",
        'webua': FULL_UA,
        'duplatform': "android",
        'appId': "duapp",
        'duchannel': "huawei",
        'humeChannel': "",
        'duv': VERSION,
        'duloginToken': "",
        'dudeviceTrait': DEVICE_TRAIT,
        'dudeviceBrand': DEVICE_BRAND,
        'timestamp': timestamp,
        'shumeiid': SHUMEII,
        'User-Agent': USER_AGENT,
        'X-Auth-Token': "Bearer+",
        'isRoot': "0",
        'emu': "0",
        'isProxy': "1",
        'SK': "",
        'edk': DEFAULT_EDK,
        'dps': "1",
        'sks': "0%2Cadw2",
        'skc': DEVICE_SKC,
        'Host': "m.dewu.com",
        'Connection': "Keep-Alive",
    }


def _captcha_headers(timestamp: str, token: str) -> dict:
    """发送验证码请求头"""
    return {
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded",
        'Host': "app.dewu.com",
        'SK': "",
        'User-Agent': USER_AGENT,
        'X-Auth-Token': token,
        'adi': DEVICE_ADI,
        'appId': "duapp",
        'app_build': "5.60.0.10",
        'cookieToken': "",
        'dps': "1",
        'duchannel': "huawei",
        'dudeviceBrand': DEVICE_BRAND,
        'dudeviceTrait': DEVICE_TRAIT,
        'duloginToken': "",
        'duplatform': "android",
        'duv': VERSION,
        'edk': DEFAULT_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': "14.212.23.140",
        'isProxy': "1",
        'isRoot': "0",
        'ltk': DEVICE_LTK,
        'shumeiid': SHUMEII,
        'skc': DEVICE_SKC,
        'sks': "0,adw2",
        'timestamp': timestamp,
        'webua': FULL_UA,
    }


def _login_headers(timestamp: str, token: str) -> dict:
    """登录请求头"""
    return {
        'Connection': "Keep-Alive",
        'Content-Type': "application/json; charset=utf-8",
        'Host': "app.dewu.com",
        'SK': "",
        'User-Agent': USER_AGENT,
        'X-Auth-Token': token,
        'adi': DEVICE_ADI,
        'appId': "duapp",
        'app_build': "5.60.0.10",
        'cookieToken': "",
        'dps': "1",
        'duchannel': "huawei",
        'dudeviceBrand': DEVICE_BRAND,
        'dudeviceTrait': DEVICE_TRAIT,
        'duloginToken': "",
        'duplatform': "android",
        'duv': VERSION,
        'edk': DEFAULT_EDK,
        'emu': "0",
        'humeChannel': "",
        'ipvx': "14.212.23.140",
        'isProxy': "1",
        'isRoot': "0",
        'ltk': DEVICE_LTK,
        'rtk': "A58rSdVApBgxO5l6Ns5U166L23M6",
        'shumeiid': SHUMEII,
        'skc': DEVICE_SKC,
        'sks': "0,adw2",
        'timestamp': timestamp,
        'webua': FULL_UA,
    }


def dewu_auth_headers(context: DewuContext) -> dict:
    """已认证请求头（精简版）"""
    return {
        'X-Auth-Token': context.token,
        'edk': context.edk,
        'User-Agent': USER_AGENT,
    }


# ==================== 核心API ====================
def get_init_token(timestamp: Optional[str] = None, timeout: int = 20) -> str:
    """
    获取初始化token（X-Auth-Token）
    从client/init接口的响应头中获取
    """
    timestamp = timestamp or current_timestamp_ms()
    query = {'webUserAgent': "", 'ipvx': "14.212.23.140", 'isNewInstall': "0"}
    new_sign = build_get_new_sign(query, timestamp)
    url = "http://m.dewu.com/client/init?" + urllib.parse.urlencode({**query, 'newSign': new_sign})

    response = requests.get(url, headers=_init_headers(timestamp), timeout=timeout)
    response.raise_for_status()

    token = response.headers.get("X-Auth-Token", "")
    if not token:
        raise RuntimeError("X-Auth-Token not found in init response headers")
    return token


def send_dewu_captcha(phone: str, init_token: Optional[str] = None, timeout: int = 20) -> CaptchaResult:
    """
    发送验证码
    init_token 可复用上次的 init token（485滑块验证后重试时与抓包行为一致：同会话token重发）
    """
    timestamp = current_timestamp_ms()
    token = init_token or get_init_token(timestamp, timeout=timeout)
    encrypted_mobile = build_encrypted_mobile(phone)

    data = {
        'msgType': "0",
        'typeId': "1",
        'riskTypeId': "1",
        'mobile': encrypted_mobile,
        'countryCode': "86",
        'cipherParam': "mobile",
        'sign': SIGN_FIXED,
    }
    new_sign = build_post_new_sign(data, timestamp)
    url = f"https://app.dewu.com/api/v1/app/user/ice/user/sendCaptcha?newSign={new_sign}"

    response = requests.post(
        url,
        data=data,
        headers=_captcha_headers(timestamp, token),
        timeout=timeout,
        allow_redirects=True,
    )

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
    r = requests.post(
        "https://app.dewu.com/api/app/risk-stone-captcha/captcha/app_call",
        json=body,
        headers=_risk_stone_headers(),
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def risk_stone_verify(session_id: str, d_payload: str, sign: str, timeout: int = 20) -> dict:
    """提交滑块轨迹验证。d=加密轨迹串（构造算法见todo#7），sign=轨迹MD5"""
    body = {
        'd': d_payload,
        'sign': sign,
        'sessionID': session_id,
        'lang': "zh",
        'platform': "android",
        'a': "0",
    }
    r = requests.post(
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
    init_token: Optional[str] = None,
    timeout: int = 20,
) -> LoginResult:
    """
    验证码登录得物
    """
    timestamp = current_timestamp_ms()
    token = init_token or get_init_token(timestamp, timeout=timeout)
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
    new_sign = build_post_new_sign(payload, timestamp)
    # 真机getVisitorUserId样本实证：user_core域newSign放body（ice域sendCaptcha才放query）
    payload['newSign'] = new_sign

    response = requests.post(
        url,
        json=payload,
        headers=_login_headers(timestamp, token),
        timeout=timeout,
        allow_redirects=True,
    )
    response.raise_for_status()

    text = urllib.parse.unquote(response.text)
    auth_token = (
        response.headers.get("X-Auth-Token", "")
        or response.headers.get("Authorization", "")
    ).strip()

    code = _extract_tag(text, "code") or _extract_json_value(text, "code")
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
        success=(str(code) == "200"),
        headers=dict(response.headers),
    )


def get_oss_info(context: DewuContext, timeout: int = 20) -> dict:
    """
    获取OSS上传信息
    """
    timestamp = current_timestamp_ms()
    new_sign = build_get_new_sign({'cdnType': "2"}, timestamp,
                                  uuid_value=_session_uuid(context.token))
    response = requests.get(
        "https://app.dewu.com/sns-conf/v1/config/get-oss-info",
        params={'cdnType': "2", 'newSign': new_sign},
        headers=dewu_auth_headers(context),
        timeout=timeout,
        allow_redirects=True,
    )
    response.raise_for_status()
    return response.json()


def upload_image_to_oss(
    image_path: str,
    oss_info: dict,
    context: DewuContext,
    timeout: int = 120,
    log=lambda _msg: None,
    object_key: str = "",
) -> str:
    """
    上传图片到OSS，返回图片URL
    支持连接超时自动重试（最多3次，每次间隔5秒）
    object_key: 可选，指定对象路径；默认走正式 community 路径
    """
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
                    upload_response = requests.put(
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
        sign_response = requests.post(
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
                    upload_response = requests.put(
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
    response = requests.get(url, headers=dewu_auth_headers(context), timeout=timeout)
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
                resp = requests.put(upload_url, data=fh, headers=headers, timeout=timeout)
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
    """构建发布动态的图片参数"""
    items = [
        {
            'bandInfo': {},
            'pictureTemplate': 0,
            'realShot': False,
            'tagPosition': [],
            'url': image_url,
        }
        for image_url in image_urls
    ]
    return json.dumps(items, ensure_ascii=False)


def build_product_content_tags(product_ids: list) -> str:
    """构建关联商品标签"""
    tags = []
    for product_id in product_ids:
        tags.append({
            'dir': 0,
            'extraId': "0",
            'extraInfo': {'goodsId': "0", 'goodsType': "0", 'show': 0},
            'id': str(product_id),
            'sourceType': "4",
            'tagSource': 0,
            'type': "3",
            'width': 0,
            'x': 0,
            'y': 0,
        })
    return json.dumps(tags, ensure_ascii=False)


def search_topic_id(topic: str, context: DewuContext, timeout: int = 20) -> str:
    """搜索话题ID"""
    topic = topic.lstrip("#＃").strip()
    new_sign = build_post_new_sign({"keyword": topic}, current_timestamp_ms(),
                                   uuid_value=_session_uuid(context.token))
    response = requests.post(
        f"https://app.dewu.com/sns-cnt-tag/v1/tag/search-tags?newSign={new_sign}",
        data={"keyword": topic},
        headers=dewu_auth_headers(context),
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
    # 组装文案内容
    normalized_topics = [line.strip() for line in topics.replace("\r\n", "\n").split("\n") if line.strip()]
    topic_content = "".join(f"#{topic}\n" for topic in normalized_topics)
    article_content = content + "\n" if content else ""
    friend_content = f"@{friend}\n" if friend else ""
    final_content = article_content + friend_content + topic_content

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
        # 图文发布：保持原样（图文此前验证可用）
        payload = {
            'trendId': "0",
            'content': final_content,
            'videoFrame': video_frame or "",
            'videoUrl': video_url or "",
            'city': "",
            'products': "",
            'from': "0",
            'images': images_payload,
            'tagId': "",
            'atUserList': "",
            'lng': "0.0",
            'lat': "0.0",
            'title': title or "",
            'sharpInfo': topic_tags,
            'priori': "0",
            'newStruct': "1",
            'commercialBrand': "",
            'pic': "2",
            'word': "38",
            'orderId': "",
            'videoBandInfo': video_band_info,
            'template': "",
            'userShowStatus': "0",
            'contentTags': product_content_tags,
            'extraData': '{"v536RemianTask":"0"}',
            'newtouch': "1",
        }

    last_text = ""
    fail_message = ""
    for attempt_no in range(1, retries + 1):
        try:
            new_sign = build_post_new_sign(payload, current_timestamp_ms(),
                                           uuid_value=_session_uuid(context.token))
            response = requests.post(
                f"https://app.dewu.com/sns-cnt-center/v1/content/trend-publish?newSign={new_sign}",
                data=payload,
                headers=dewu_auth_headers(context),
                timeout=timeout,
                allow_redirects=True,
            )
            response.raise_for_status()  # 非2xx会抛HTTPError
            parsed_text = urllib.parse.unquote(response.text)
        except requests.exceptions.RequestException as exc:
            last_text = f"发布请求异常: {exc}"
            fail_message = f"发布请求失败（第{attempt_no}/{retries}次）: {exc}"
        else:
            last_text = parsed_text
            details = _parse_publish_response_details(last_text)
            if details.get("content_id", ""):
                return PublishResult(
                    success=True,
                    response_text=last_text,
                    message=_extract_json_value(last_text, "msg") or "发布成功",
                    http_status=200,
                    content_id=details.get("content_id", ""),
                    article_url=details.get("article_url", ""),
                )
            fail_message = f"HTTP 200但未返回文章ID，发布未落地：{_publish_response_diagnostic(last_text)}"
        if attempt_no < retries:
            time.sleep(2 + attempt_no)  # 失败后递增退避再重试

    return PublishResult(
        success=False,
        response_text=last_text,
        message=fail_message or (_extract_json_value(last_text, "msg") or "发布失败"),
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
