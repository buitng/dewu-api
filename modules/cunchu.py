"""状态模块：全局运行状态单例 + JSON 持久化

所有功能模块统一通过 state 读取/修改共享状态，
避免全局变量散落在各文件中导致难以维护。
"""
import json
import threading
from pathlib import Path

# 项目根目录（本文件位于 modules/ 子目录下）
GEN_DIR = Path(__file__).resolve().parent.parent

# 持久化文件路径
STATE_FILE = GEN_DIR / 'publisher_state.json'
MATERIAL_FILE = GEN_DIR / 'material_library.json'
USED_CONTENT_FILE = GEN_DIR / 'used_content.json'

# AI 默认配置
DEFAULT_AI_CONFIG = {
    'provider': 'template',  # template / doubao / openai / ollama
    'api_key': '',
    'model': 'doubao-pro-32k',
    'base_url': 'https://ark.cn-beijing.volces.com/api/v3',
    'temperature': 0.85,
    'max_tokens': 3000,
    'gender': 'neutral',  # 目标人群：auto / male / female / neutral
    'category': 'auto',  # 品类：auto / 衬衫 / T恤 / 裤子等
}


class Zhuangtai:
    """运行时共享状态（单例）"""

    def __init__(self):
        # ---- 账号 ----
        self.accounts = {}  # phone -> {token, user_id, user_name, login_time}
        self.current_account = None
        # ---- 图文发布 ----
        self.publish_tasks = []
        self.publish_running = False
        # ---- 视频发布 ----
        self.video_tasks = []
        self.video_publish_running = False
        # ---- 素材库 ----
        self.material_library = []
        self.fetch_api_url = ''
        # ---- AI 配置 / 趋势词 ----
        self.ai_config = dict(DEFAULT_AI_CONFIG)
        self.trend_words = []
        # ---- 多任务队列 ----
        self.task_queue = []
        self.task_queue_running = False
        self.task_queue_thread = None
        self.task_queue_lock = threading.Lock()

    # ============ 账号 / AI 配置 / 趋势词 持久化 ============
    def load_state(self):
        """加载保存的状态（恢复 AI 配置 / 趋势词 / 模拟器导入账号）。

        登录状态处理分两类：
        - 模拟器导入账号（source=emulator 且有 token）：跨重启保留（App 正常登录态，
          一年有效期，无风控会话漂移问题）
        - 短信登录账号：启动即清（避免重启沿用旧会话造成风控上下文漂移）
        """
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding='utf-8'))
                if 'ai_config' in data:
                    self.ai_config.update(data['ai_config'])
                self.trend_words = list(data.get('trend_words', []))
                accounts = data.get('accounts') or {}
                kept = {k: v for k, v in accounts.items()
                        if isinstance(v, dict) and v.get('source') == 'emulator' and v.get('token')}
                changed = False
                if kept != accounts:
                    data['accounts'] = kept
                    changed = True
                if data.get('current_account') and data['current_account'] not in kept:
                    data['current_account'] = None
                    changed = True
                if changed:
                    STATE_FILE.write_text(
                        json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
                if kept:
                    self.accounts = {k: dict(v) for k, v in kept.items()}
                    self.current_account = data.get('current_account')
            except Exception:
                pass

    def save_state(self):
        """保存状态（token/login_token + 设备快照 + 当前账号；短信账号重启清、模拟器账号保留）"""
        accounts_to_save = {}
        for phone, info in self.accounts.items():
            accounts_to_save[phone] = {
                'token': info.get('token', ''),
                'login_token': info.get('login_token', ''),
                'user_id': info.get('user_id', ''),
                'user_name': info.get('user_name', ''),
                'login_time': info.get('login_time', ''),
                'device': info.get('device'),
                'source': info.get('source', ''),
            }
        data = {
            'accounts': accounts_to_save,
            'current_account': self.current_account,
            'ai_config': self.ai_config,
            'trend_words': self.trend_words,
        }
        STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

    # ============ 素材库持久化 ============
    def load_material_library(self):
        """从磁盘加载素材库与抓取API地址"""
        if MATERIAL_FILE.exists():
            try:
                data = json.loads(MATERIAL_FILE.read_text(encoding='utf-8'))
                self.material_library = list(data.get('materials', []))
                self.fetch_api_url = data.get('fetch_api_url', '')
            except Exception:
                pass

    def save_material_library(self):
        """素材库持久化到磁盘"""
        data = {
            'materials': self.material_library,
            'fetch_api_url': self.fetch_api_url,
        }
        MATERIAL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


# 全局唯一状态实例
state = Zhuangtai()
