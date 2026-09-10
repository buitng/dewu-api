"""日志模块：内存日志队列 + 磁盘日志文件（线程安全）

提供 log() 与 publish_logs，供主程序及各功能模块统一调用。
"""
import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify

# 日志文件位于项目根目录（本文件在 modules/ 子目录下）
LOG_FILE = Path(__file__).resolve().parent.parent / 'publisher_log.txt'

LOG_LOCK = threading.Lock()
publish_logs = []  # 内存日志，最多保留 500 条


def log(message: str):
    """记录日志（线程安全）：写入内存队列与磁盘文件，并输出到控制台"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{timestamp}] {message}'
    with LOG_LOCK:
        publish_logs.append(line)
        if len(publish_logs) > 500:
            del publish_logs[0]
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except OSError:
            pass
    print(line)


# 日志接口蓝图
bp = Blueprint('rizhi', __name__)


@bp.route('/api/logs')
def api_logs():
    """获取最近日志（供操作日志页面轮询）"""
    return jsonify({'logs': publish_logs[-200:]})
