"""账号模块：验证码发送 / 验证码登录 / 账号切换删除退出

通过 Flask 蓝图提供 /api/send_captcha、/api/login、/api/accounts 等接口。
共享状态统一使用 modules.cunchu.state。
"""
import json
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify

from dewu_api import (send_dewu_captcha, login_dewu_with_captcha,
                      risk_stone_call, risk_stone_verify, _plain_fail_msg)
from modules.cunchu import state
from modules.rizhi import log

bp = Blueprint('zhanghu', __name__)

# 测试手机号：发码/登录仅用于链路验证，日志标注【测试】，不影响真实账号数据
TEST_PHONES = {'13800138000'}

# 发码会话 token 缓存（phone -> init token）：验证码会话按 token+手机号匹配，
# 登录时复用同一 token（真机抓包同 token 贯穿 init→sendCaptcha→unionLogin；
# _test_full_chain60 假号全链路实证）。仅存内存，重启自动清空（登录态不跨重启）。
_pending_login_tokens = {}


@bp.route('/api/send_captcha', methods=['POST'])
def api_send_captcha():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'success': False, 'message': '手机号不能为空'})
    try:
        # 设备已静态化为 MIX 2S 真机指纹（发码走白盒 data= 重放，无需随机换设备绕风控）
        tag = '【测试】' if phone in TEST_PHONES else ''
        result = send_dewu_captcha(phone)
        # 发码成功即缓存该会话 token，登录时复用（会话统一，见 _pending_login_tokens 注释）
        if result.success and result.token:
            _pending_login_tokens[phone] = result.token
        # 发码结果落日志（此前为盲区：无法确认短信是否真的发出）
        log(f"{tag}发码结果[{phone}]: success={result.success} msg={result.message}"
            + (" [滑块挑战]" if result.challenge else ""))
        resp = {
            'success': result.success,
            'message': result.message,
        }
        if result.challenge:
            resp.update({
                'need_captcha': True,
                'session_id': result.challenge.get('sessionId', ''),
                'challenge_type': result.challenge.get('type'),
                'message': '触发风控滑块验证，请完成滑块后重试',
            })
        return jsonify(resp)
    except Exception as e:
        log(f'发送验证码失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/captcha/challenge', methods=['POST'])
def api_captcha_challenge():
    """拉取滑块/点选挑战图（app_call 明文代理）"""
    data = request.json
    session_id = data.get('session_id', '').strip()
    if not session_id:
        return jsonify({'success': False, 'message': 'session_id不能为空'})
    try:
        rj = risk_stone_call(session_id)
        if str(rj.get('code')) != '1':
            return jsonify({'success': False, 'message': rj.get('msg', '拉取挑战失败'), 'raw': rj})
        d = rj.get('data') or {}
        return jsonify({
            'success': True,
            'session_id': d.get('sessionId') or session_id,
            'bg_image': d.get('bgImage', ''),
            'bg_list': d.get('bgList', []),
        })
    except Exception as e:
        log(f'拉取滑块挑战失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/captcha/verify', methods=['POST'])
def api_captcha_verify():
    """提交滑块验证。

    两种模式：
    - track: 前端采集的轨迹数组 [{x,y,t}]，后端打包加密为d串（构造算法待todo#7）
    - d/sign: 直接透传已构造好的d串（todo#7联调用）
    """
    data = request.json
    session_id = (data.get('session_id') or '').strip()
    track = data.get('track')
    d_payload = data.get('d', '')
    sign = data.get('sign', '')

    if not session_id:
        return jsonify({'success': False, 'message': 'session_id不能为空'})

    if track and not d_payload:
        return jsonify({
            'success': False,
            'message': f'轨迹已采集（{len(track)}点），d串加密打包模块开发中（todo#7：数美轨迹加密）',
        })

    if not d_payload:
        return jsonify({'success': False, 'message': 'track或d不能为空'})
    try:
        rj = risk_stone_verify(session_id, d_payload, sign)
        return jsonify({
            'success': str(rj.get('code')) == '1',
            'message': rj.get('msg', ''),
            'raw': rj if str(rj.get('code')) != '1' else None,
        })
    except Exception as e:
        log(f'滑块验证提交失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    phone = data.get('phone', '').strip()
    captcha = data.get('captcha', '').strip()
    if not phone or not captcha:
        return jsonify({'success': False, 'message': '手机号和验证码不能为空'})
    try:
        # ★会话统一：复用发码时的 init token（验证码会话按 token+手机号匹配，
        # 真机抓包同 token 贯穿 init→sendCaptcha→unionLogin；
        # 发码 token 本就是 6.0 init 签发，与 unionLogin 6.0 门禁同源，无混搭风险）
        # 挑战/失败不丢会话（get 而非 pop）：同码可重试同一验证码会话，成功后才清除。
        # http_log 实证：此前 pop 后重试登录会自 init 新取 token 开新会话，旧码对不上
        pending_token = _pending_login_tokens.get(phone)
        log(f'登录请求[{phone}]: 验证码长度={len(captcha)} '
            f'复用发码会话token={"是" if pending_token else "否(自init新取)"}')
        result = login_dewu_with_captcha(phone, captcha, init_token=pending_token)
        # 485 风控滑块挑战：返回 need_captcha 供前端走已有滑块 UI（与发码挑战同形态）
        if result.challenge:
            ch = result.challenge
            return jsonify({
                'success': False,
                'need_captcha': True,
                'session_id': ch.get('sessionId', ''),
                'challenge_type': ch.get('type'),
                'message': getattr(result, 'message', '') or 'unionLogin 触发风控滑块，请完成滑块后重试',
            })
        if result.success:
            state.accounts[phone] = {
                'token': result.token,
                # loginToken（unionLogin accessToken）：请求头 duloginToken/cookieToken 用
                'login_token': getattr(result, 'login_token', ''),
                'user_id': result.user_id,
                'user_name': result.user_name,
                'login_time': datetime.now().isoformat(),
            }
            state.current_account = phone
            state.save_state()
            _pending_login_tokens.pop(phone, None)  # 会话已消费，清除缓存
            log(f'登录成功: {phone} ({result.user_name})')
        if not result.success:
            msg = result.response_text[:200]
            # 完整响应+响应头记入日志（排查风控错误码用，页面只显示摘要）
            log(f'登录原始响应: {result.response_text}')
            log(f'登录响应头: {result.headers if hasattr(result, "headers") else "(未记录)"}')
            try:
                code = str(json.loads(result.response_text).get('code') or '')
            except Exception:
                code = ''
            if code == '714':
                # 解密显示服务端真实 msg（如"账号或验证码错误"），附操作建议
                real = _plain_fail_msg(result.response_text)
                msg = (f'登录失败（714）：{real}\n'
                       '验证码可能已过期/已使用，请重新发送验证码并尽快（60秒内）点击登录；'
                       '若仍失败，建议更换网络环境（如切换手机热点）或间隔1小时后再试。')
            elif code == '794':
                # 解密实证（_dec794）：794 加密 data 内 msg="请1分钟后再试"——频率限制而非滑块
                msg = ('登录请求触发频率限制（服务端提示：请1分钟后再试）。\n'
                       '请等待 1-2 分钟后重新发送验证码并登录，不要连续快速重试。')
            elif code == '20006':
                # 20006但未换取到有效JWT（accessToken解密失败等）：
                # 服务端msg是"通过"，直接透传会显示"登录失败：通过"造成误解
                msg = ('登录响应异常（20006但未取得有效会话token），可能为内容解析失败，'
                       '请重新发送验证码后重试；若连续出现请查看日志。')
            elif code and code not in ('200',):
                msg = f'登录失败：{_plain_fail_msg(result.response_text)}'
        # 附加说明（如游客态降级提示）优先于默认文案
        final_msg = getattr(result, 'message', '') or ('登录成功' if result.success else msg)
        return jsonify({
            'success': result.success,
            'message': final_msg,
        })
    except Exception as e:
        log(f'登录失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/import_emulator_token', methods=['POST'])
def api_import_emulator_token():
    """从模拟器 root 直读登录态 JWT 导入账号（路线B接网页，零抓包）。

    流程：adb 连模拟器 -> su cat App 私有 MMKV -> 提取登录态 JWT（isGuest=false，
    取 exp 最新）+ duToken -> 存入 accounts（source=emulator）-> 设为当前账号。
    模拟器账号一年有效期且跨重启保留（见 cunchu.load_state）。
    """
    try:
        import huoqu_token  # 延迟导入：模块级 find_adb 等仅在此路由首次使用时执行
        hit = huoqu_token.read_token_for_web()
        if not hit:
            return jsonify({'success': False, 'message':
                '未读到登录态 token：请先在模拟器得物App里登录账号（游客态会被跳过），再点导入'})
        raw, jp, du_tok, src = hit
        uid = str(jp.get('userId') or '')
        if not uid:
            return jsonify({'success': False, 'message': 'JWT 里没有 userId，token 异常'})
        exp = jp.get('exp') or 0
        exp_str = datetime.fromtimestamp(exp).strftime('%Y-%m-%d') if exp else '未知'
        # JWT 不含手机号，账号键用 uid（前端展示昵称 + uid）
        state.accounts[uid] = {
            'token': raw,
            'login_token': du_tok or '',   # duToken 原样（可带 duToken= 前缀，发布时拼复合串）
            'user_id': uid,
            'user_name': jp.get('userName') or '',
            'login_time': datetime.now().isoformat(),
            'source': 'emulator',
            'token_exp': exp,
        }
        state.current_account = uid
        state.save_state()
        log(f'模拟器导入账号: uid={uid} ({jp.get("userName")}) 来源={src} token过期={exp_str}')
        return jsonify({'success': True, 'message':
            f'导入成功：{jp.get("userName") or uid}（uid={uid}），token 有效期至 {exp_str}，已设为当前账号'})
    except RuntimeError as e:
        return jsonify({'success': False, 'message': str(e)})
    except Exception as e:
        log(f'模拟器导入失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': f'导入失败：{e}'})


@bp.route('/api/accounts')
def api_accounts():
    result = []
    for phone, info in state.accounts.items():
        result.append({
            'phone': phone,
            'user_id': info.get('user_id', ''),
            'user_name': info.get('user_name', ''),
            'current': phone == state.current_account,
            # token 状态：持久化后前端显示"登录中/无token"
            'has_token': bool(info.get('token', '')),
            'login_time': info.get('login_time', ''),
            'source': info.get('source', ''),
        })
    return jsonify({'accounts': result})


@bp.route('/api/use_account', methods=['POST'])
def api_use_account():
    data = request.json
    phone = data.get('phone', '')
    if phone in state.accounts:
        state.current_account = phone
        state.save_state()
        log(f'切换账号: {phone}')
    return jsonify({'success': True})


@bp.route('/api/remove_account', methods=['POST'])
def api_remove_account():
    data = request.json
    phone = data.get('phone', '')
    if phone in state.accounts:
        # 真正删除：从accounts中彻底移除
        del state.accounts[phone]
        # 如果删除的是当前登录账号，清除当前登录状态
        if state.current_account == phone:
            state.current_account = None
            log(f'已删除当前登录账号: {phone}，当前登录状态已清除')
        else:
            log(f'已删除账号: {phone}')
        state.save_state()
    return jsonify({'success': True})


@bp.route('/api/logout', methods=['POST'])
def api_logout():
    """退出当前登录账号：清除登录态（账号昵称信息保留显示）"""
    if state.current_account:
        phone = state.current_account
        info = state.accounts.get(phone)
        if info is not None:
            info['token'] = ''
            info['login_token'] = ''
        state.current_account = None
        state.save_state()
        log(f'用户退出登录: {phone}（登录态已清除）')
    return jsonify({'success': True})
