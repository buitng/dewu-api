"""素材库模块：素材增删改查、外网内容抓取、素材一键发布

由 dewu_web.py 拆分而来，通过蓝图提供 /api/materials 系列接口。
图文/视频发布复用 modules.fabu / modules.shipin 的工作线程。
"""
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request

from modules.cunchu import state
from modules.fabu import publish_worker
from modules.rizhi import log
from modules.shipin import video_publish_worker

bp = Blueprint('sucai', __name__)


@bp.route('/api/materials', methods=['GET'])
def api_get_materials():
    """获取素材列表"""
    return jsonify({'materials': state.material_library, 'fetch_api_url': state.fetch_api_url})


@bp.route('/api/materials/save', methods=['POST'])
def api_save_material():
    """保存素材"""
    data = request.json
    material = {
        'id': data.get('id') or str(int(time.time() * 1000)),
        'title': data.get('title', ''),
        'content': data.get('content', ''),
        'topics': data.get('topics', ''),
        'goods_id': data.get('goods_id', ''),
        'media_urls': data.get('media_urls', []),
        'media_type': data.get('media_type', 'image'),  # image / video
        'source_url': data.get('source_url', ''),
        'created_at': datetime.now().isoformat(),
    }
    # 如果有id则更新，否则新增
    existing = next((m for m in state.material_library if m['id'] == material['id']), None)
    if existing:
        existing.update(material)
        log(f'素材已更新: {material["title"][:20]}')
    else:
        state.material_library.insert(0, material)
        log(f'素材已保存: {material["title"][:20]}')
    state.save_material_library()
    return jsonify({'success': True, 'material': material})


@bp.route('/api/materials/delete', methods=['POST'])
def api_delete_material():
    """删除素材"""
    data = request.json
    material_id = data.get('id', '')
    state.material_library = [m for m in state.material_library if m['id'] != material_id]
    state.save_material_library()
    log(f'素材已删除: {material_id}')
    return jsonify({'success': True})


@bp.route('/api/materials/fetch', methods=['POST'])
def api_fetch_material():
    """抓取外网内容"""
    data = request.json
    url = data.get('url', '').strip()
    api = data.get('api_url', '').strip() or state.fetch_api_url
    
    if not url:
        return jsonify({'success': False, 'message': '请输入外网链接'})
    if not api:
        return jsonify({'success': False, 'message': '请先配置抓取API地址'})
    
    try:
        log(f'开始抓取外网内容: {url}')
        response = requests.get(api, params={'url': url}, timeout=30)
        response.raise_for_status()
        result = response.json()
        
        # 解析返回结果（兼容不同的API返回格式）
        material = {
            'title': result.get('title', '') or result.get('data', {}).get('title', ''),
            'content': result.get('content', '') or result.get('desc', '') or result.get('data', {}).get('content', ''),
            'topics': result.get('topics', '') or (', '.join(result.get('tags', [])) if isinstance(result.get('tags'), list) else ''),
            'media_urls': result.get('images', []) or result.get('media_list', []) or result.get('data', {}).get('images', []),
            'media_type': 'video' if result.get('video_url') or result.get('video') else 'image',
            'source_url': url,
        }
        
        # 如果有视频URL，添加到media_urls
        if result.get('video_url'):
            material['media_urls'] = [result['video_url']]
            material['media_type'] = 'video'
        
        log(f'抓取成功: {material["title"][:20]}，共 {len(material["media_urls"])} 个媒体文件')
        return jsonify({'success': True, 'material': material})
    except Exception as e:
        log(f'抓取失败: {e}')
        return jsonify({'success': False, 'message': f'抓取失败: {str(e)}'})


@bp.route('/api/materials/fetch_api_url', methods=['POST'])
def api_set_fetch_api_url():
    """设置抓取API地址"""
    data = request.json
    state.fetch_api_url = data.get('api_url', '').strip()
    state.save_material_library()
    log(f'抓取API地址已更新: {state.fetch_api_url}')
    return jsonify({'success': True})


@bp.route('/api/materials/publish', methods=['POST'])
def api_publish_material():
    """素材一键发布"""
    if state.publish_running:
        return jsonify({'success': False, 'message': '发布任务正在运行中'})
    if not state.current_account:
        return jsonify({'success': False, 'message': '请先登录账号'})
    
    data = request.json
    material_id = data.get('id', '')
    material = next((m for m in state.material_library if m['id'] == material_id), None)
    if not material:
        return jsonify({'success': False, 'message': '素材不存在'})
    
    # 下载媒体文件到本地
    import urllib.request
    local_media_paths = []
    try:
        log(f'开始下载素材媒体文件: {material["title"][:20]}')
        for i, media_url in enumerate(material.get('media_urls', [])):
            if not media_url:
                continue
            ext = '.jpg' if material['media_type'] == 'image' else '.mp4'
            local_path = Path(__file__).parent / 'temp_media' / f'material_{material_id}_{i}{ext}'
            local_path.parent.mkdir(exist_ok=True)
            try:
                urllib.request.urlretrieve(media_url, str(local_path))
                local_media_paths.append(str(local_path))
                log(f'  媒体文件下载完成: {local_path.name}')
            except Exception as e:
                log(f'  媒体文件下载失败: {e}')
    except Exception as e:
        log(f'媒体文件下载异常: {e}')
    
    if not local_media_paths:
        return jsonify({'success': False, 'message': '媒体文件下载失败，无法发布'})
    
    # 构建发布任务
    if material['media_type'] == 'video':
        # 视频发布
        video_task = {
            'title': material['title'],
            'dir': str(Path(local_media_paths[0]).parent),
            'videos': local_media_paths,
            'video_count': len(local_media_paths),
            'status': 'pending',
            'status_text': '待发布',
            'article_url': '',
        }
        state.video_tasks.clear()
        state.video_tasks.append(video_task)

        state.video_publish_running = True
        thread = threading.Thread(
            target=video_publish_worker,
            args=(material.get('goods_id', ''), 0),
            daemon=True,
        )
        thread.start()
        log(f'素材视频发布已启动: {material["title"][:20]}')
    else:
        # 图文发布
        image_task = {
            'title': material['title'],
            'dir': str(Path(local_media_paths[0]).parent),
            'images': local_media_paths,
            'image_count': len(local_media_paths),
            'status': 'pending',
            'status_text': '待发布',
            'article_url': '',
        }
        state.publish_tasks.clear()
        state.publish_tasks.append(image_task)
        
        state.publish_running = True
        thread = threading.Thread(
            target=publish_worker,
            args=(material['title'], material['content'], material['topics'], material.get('goods_id', ''), 0, False),
            daemon=True,
        )
        thread.start()
        log(f'素材图文发布已启动: {material["title"][:20]}')
    
    return jsonify({'success': True, 'message': '发布任务已启动'})
