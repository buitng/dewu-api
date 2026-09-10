"""账号模块：验证码发送 / 验证码登录 / 账号切换删除退出

通过 Flask 蓝图提供 /api/send_captcha、/api/login、/api/accounts 等接口。
共享状态统一使用 modules.cunchu.state。
"""
import json
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify

from dewu_api import (send_dewu_captcha, login_dewu_with_captcha,
                      risk_stone_call, risk_stone_verify, randomize_device)
from modules.cunchu import state
from modules.rizhi import log

bp = Blueprint('zhanghu', __name__)


@bp.route('/api/send_captcha', methods=['POST'])
def api_send_captcha():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'success': False, 'message': '手机号不能为空'})
    try:
        # 每次发码前更换整套设备身份（实证：换shumeiid即可绕过485滑块，整套随机更稳）
        dev = randomize_device()
        log(f"已更换设备: {dev['brand']} {dev['trait']} (Android {dev['android']}) shumeiid={dev['shumeiid']}")
        # 新设备不复用旧init token（旧token属于上一个设备会话，复用会上下文不一致）
        result = send_dewu_captcha(phone)
        # 无论成功或485，都记录token：485重试需复用同一token上下文
        state.pending_captcha_tokens[phone] = result.token
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
        # 复用发送验证码时的init token（登录接口要求与发码保持同一设备token上下文）
        init_token = state.pending_captcha_tokens.pop(phone, None)
        result = login_dewu_with_captcha(phone, captcha, init_token=init_token)
        if result.success:
            state.accounts[phone] = {
                'token': result.token,
                'user_id': result.user_id,
                'user_name': result.user_name,
                'login_time': datetime.now().isoformat(),
            }
            state.current_account = phone
            state.save_state()
            log(f'登录成功: {phone} ({result.user_name})')
        if not result.success:
            msg = result.response_text[:200]
            try:
                code = str(json.loads(result.response_text).get('code') or '')
            except Exception:
                code = ''
            if code == '714':
                msg = ('登录被风控拦截（code 714）。可能原因：验证码已过期/已使用、操作频率过快、'
                       '或当前设备环境被识别为风险。\n请重新发送验证码并尽快（60秒内）点击登录；'
                       '若仍失败，建议更换网络环境（如切换手机热点）或间隔1小时后再试。')
            elif code and code not in ('200',):
                msg = f'登录失败（code {code}）。原始返回：{result.response_text[:150]}'
        return jsonify({
            'success': result.success,
            'message': '登录成功' if result.success else msg,
        })
    except Exception as e:
        log(f'登录失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/accounts')
def api_accounts():
    result = []
    for phone, info in state.accounts.items():
        result.append({
            'phone': phone,
            'user_id': info.get('user_id', ''),
            'user_name': info.get('user_name', ''),
            'current': phone == state.current_account,
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
    """退出当前登录账号"""
    if state.current_account:
        log(f'用户退出登录: {state.current_account}')
        state.current_account = None
        state.save_state()
    return jsonify({'success': True})
