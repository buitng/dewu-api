# -*- coding: utf-8 -*-
# 实验：换设备码是否绕过 485 滑块
# 变体：仅换 shumeiid（随机 64hex），其余头/参数不动 → 发一次 sendCaptcha 看风控反应
import sys, io, os, json, secrets
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import dewu_api as D

variant = sys.argv[1] if len(sys.argv) > 1 else "shumeiid"

if variant == "shumeiid":
    # 仅换数美设备 ID
    D.SHUMEII = secrets.token_hex(32)  # 64 hex
    print(f"[variant] SHUMEII -> {D.SHUMEII}")
elif variant == "full2":
    # 整套随机设备（dewu_api.randomize_device：机型+UA+全部标识）
    snap = D.randomize_device()
    print(f"[variant] randomize_device -> {snap}")
else:
    print(f"[variant] baseline（原设备）")

phone = "13800138000"
print(f"[run] init_token ...")
ts = D.current_timestamp_ms()
token = D.get_init_token(ts)
print(f"[run] token={token[:40]}...")

res = D.send_dewu_captcha(phone, init_token=token)

print(f"[result] success={res.success} msg={res.message}")
print(f"[result] http_body={res.response_text[:300]}")
if res.challenge:
    print(f"[result] CHALLENGE(滑块) sessionId={res.challenge.get('sessionId')}")
