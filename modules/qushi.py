"""趋势词模块：得物搜索趋势词管理

由 dewu_web.py 拆分而来，通过蓝图提供 /api/trend_words。
"""
from flask import Blueprint, jsonify, request

from modules.cunchu import state
from modules.rizhi import log

bp = Blueprint('qushi', __name__)


@bp.route('/api/trend_words', methods=['GET', 'POST'])
def api_trend_words():
    if request.method == 'GET':
        return jsonify({'words': state.trend_words, 'count': len(state.trend_words)})
    else:
        data = request.json
        action = data.get('action', 'set')
        if action == 'set':
            # 批量追加（不覆盖之前的趋势词），支持换行、逗号、空格分隔
            raw = data.get('words', '')
            new_words = []
            for line in raw.replace(',', '\n').replace('，', '\n').replace(' ', '\n').split('\\n'):
                w = line.strip().replace('#', '')
                if w and w not in new_words and w not in state.trend_words:
                    new_words.append(w)
            # 追加到现有趋势词后面
            state.trend_words.extend(new_words)
            state.save_state()
            log(f'趋势词已追加 {len(new_words)} 个新趋势词，当前共 {len(state.trend_words)} 个')
            return jsonify({'success': True, 'count': len(state.trend_words), 'added': len(new_words)})
        elif action == 'add':
            word = data.get('word', '').strip().replace('#', '')
            if word and word not in state.trend_words:
                state.trend_words.append(word)
                state.save_state()
                log(f'添加趋势词: {word}')
            return jsonify({'success': True, 'count': len(state.trend_words)})
        elif action == 'clear':
            state.trend_words = []
            state.save_state()
            log('清空所有趋势词')
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': '未知操作'})
