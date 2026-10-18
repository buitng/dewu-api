"""视频发布模块：视频扫描、视频标题生成、视频发布工作线程

由 dewu_web.py 拆分而来，通过蓝图提供 /api/scan_videos、/api/video_tasks、
/api/start_video_publish、/api/stop_video_publish、/api/clear_video_tasks。
"""
import json
import os
import random
import re
import threading
import time
import traceback
from pathlib import Path

from flask import Blueprint, jsonify, request

from dewu_api import (
    DewuContext,
    get_oss_info,
    get_video_oss_info,
    upload_image_to_oss,
    build_product_content_tags,
    publish_trend,
    upload_video_to_oss,
    upload_video_to_dewu_oss,
    extract_video_frame,
    build_video_band_info,
)
from modules.cunchu import state
from modules.gongju import natural_sort_key, random_delay
from modules.rizhi import log
from modules.shengcheng import (
    call_chat_api,
    extract_product_info_from_path,
    generate_unique_content,
    parse_product_info,
)

bp = Blueprint('shipin', __name__)


VIDEO_EXTENSIONS = {'.mp4', '.mov', '.avi', '.mkv', '.flv', '.wmv'}

def scan_videos(dir_path: str) -> list:
    """扫描视频文件"""
    videos = []
    dir_path = Path(dir_path)
    if not dir_path.exists():
        return videos
    
    # 扫描子文件夹中的视频
    for item in sorted(dir_path.iterdir()):
        if item.is_dir():
            folder_videos = []
            for f in sorted(item.iterdir(), key=natural_sort_key):
                if f.is_file() and f.suffix.lower() in VIDEO_EXTENSIONS:
                    folder_videos.append(str(f))
            if folder_videos:
                videos.append({
                    'dir': str(item),
                    'title': item.name,
                    'videos': folder_videos,
                    'video_count': len(folder_videos),
                    'status': 'pending',
                    'status_text': '待发布',
                    'article_url': '',
                })
        elif item.is_file() and item.suffix.lower() in VIDEO_EXTENSIONS:
            # 根目录下的视频
            videos.append({
                'dir': str(dir_path),
                'title': item.stem,
                'videos': [str(item)],
                'video_count': 1,
                'status': 'pending',
                'status_text': '待发布',
                'article_url': '',
            })
    
    return videos


def generate_video_title(product_info: dict) -> str:
    """AI生成视频标题（只生成标题，不生成文案）"""
    try:
        provider = state.ai_config.get('provider', 'template')
        if provider == 'template':
            # 使用模板生成标题
            sku = product_info.get('sku', '')
            color = product_info.get('color', '')
            category = product_info.get('category', '服饰')
            gender = product_info.get('gender', 'neutral')
            
            gender_map = {'male': '男生', 'female': '女生', 'neutral': '男女'}
            person = gender_map.get(gender, '男女')
            
            color_desc = f'{color}色' if color and not color.endswith('色') else (color or '')
            
            title_templates = [
                f'{person}早秋穿搭｜{color_desc}{category}开箱',
                f'好物分享｜{sku} {color_desc}{category}实测',
                f'{color_desc}{category}！{person}早秋氛围感',
                f'开箱测评｜{sku}这款{color_desc}{category}到底值不值',
                f'{person}必入｜{color_desc}{category}穿搭分享',
                f'早秋穿搭｜{color_desc}{category}一衣多穿',
                f'真实测评｜穿了一周的{color_desc}{category}',
                f'{sku}开箱｜{color_desc}{category}也太好看了吧',
            ]
            import random
            return random.choice(title_templates)
        else:
            # 使用AI生成标题
            prompt = f"""你是一个得物平台的资深穿搭博主。请为以下商品生成一个得物视频动态标题：

商品信息：
- 货号：{product_info.get('sku', '')}
- 颜色：{product_info.get('color', '未知')}
- 品类：{product_info.get('category', '服饰')}
- 适用人群：{product_info.get('gender', '中性')}

要求：
1. 标题长度10-20字
2. 包含人群+品类+卖点
3. 吸引点击，有开箱/测评/分享的感觉
4. 可以适当使用emoji
5. 只输出标题，不要输出其他内容！

现在开始，只输出标题："""
            
            title = call_chat_api(
                base_url=state.ai_config['base_url'],
                api_key=state.ai_config['api_key'],
                model=state.ai_config['model'],
                prompt=prompt,
                temperature=state.ai_config.get('temperature', 0.85),
                max_tokens=100,
            )
            return title.strip().strip('"').strip("'")
    except Exception as e:
        log(f'视频标题生成失败，使用默认标题: {e}')
        return f'{product_info.get("sku", "好物")} 开箱分享'


def video_publish_worker(product_id="", interval_minutes=0, cover_image=""):
    """视频发布工作线程"""
    try:
        account_info = state.accounts.get(state.current_account, {})
        context = DewuContext(
            token=account_info.get('token', ''),
            user_id=account_info.get('user_id', ''),
            user_name=account_info.get('user_name', ''),
            login_token=account_info.get('login_token', ''),
        )

        log(f'开始视频发布任务，账号: {state.current_account}')
        log(f'获取视频OSS上传信息...')
        video_oss_info = get_video_oss_info(context)
        log(f'视频OSS信息获取成功（桶: {video_oss_info.get("bucketName")}）')
        # 封面图仍上传到图片OSS
        log(f'获取图片OSS上传信息（封面用）...')
        image_oss_info = get_oss_info(context)

        for i, task in enumerate(state.video_tasks):
            if not state.video_publish_running:
                log(f'视频发布任务已停止')
                break

            if task['status'] == 'success':
                continue

            task['status'] = 'running'
            task['status_text'] = '发布中'
            log(f'[{i+1}/{len(state.video_tasks)}] 正在发布视频: {task["title"]} ({task["video_count"]}个视频)')

            try:
                # 只发布第一个视频（得物每条动态只能一个视频）
                video_path = task['videos'][0]
                random_delay(1000, 2000)
                
                # 上传视频（直传得物视频桶 dw-video）
                log(f'  上传视频: {Path(video_path).name}')
                video_info = upload_video_to_dewu_oss(video_path, video_oss_info, context, log=log)
                video_url = video_info['url']
                video_band_info = build_video_band_info(video_info)
                
                # 视频封面：手动指定 > 同目录封面图 > 自动提取第一帧
                random_delay(1000, 2000)
                video_frame_url = ""
                video_dir = Path(video_path).parent

                # 手动指定的封面图（优先）
                if cover_image:
                    cover_image = str(cover_image).strip()
                    if Path(cover_image).exists():
                        log(f'  使用手动指定封面图: {Path(cover_image).name}')
                        try:
                            video_frame_url = upload_video_cover(cover_image, image_oss_info, context, log=log)
                            if video_frame_url:
                                log(f'  封面图上传成功')
                            else:
                                log(f'  封面图上传失败，尝试其他封面来源')
                        except Exception as e:
                            log(f'  手动封面图上传异常: {e}，尝试其他封面来源')
                    else:
                        log(f'  手动指定封面图不存在，尝试其他封面来源: {cover_image}')
                log(f'  视频目录: {video_dir}')
                # 列出目录中的所有图片文件，方便调试
                try:
                    all_files = list(video_dir.glob('*'))
                    image_files = [f.name for f in all_files if f.suffix.lower() in ('.jpg', '.jpeg', '.png', '.webp', '.bmp')]
                    log(f'  目录中的图片文件: {image_files}')
                except Exception:
                    pass
                # 增加更多封面图文件名匹配模式
                video_stem = Path(video_path).stem
                cover_patterns = [
                    'cover.jpg', 'cover.jpeg', 'cover.png', 'cover.webp',
                    '封面.jpg', '封面.jpeg', '封面.png', '封面.webp',
                    '封面图.jpg', '封面图.png',
                    'video_cover.jpg', 'video_cover.png',
                    f'{video_stem}_cover.jpg', f'{video_stem}_cover.png',
                    f'{video_stem}_frame.jpg', f'{video_stem}_frame.png',
                    f'{video_stem}.jpg', f'{video_stem}.png',
                ]
                for pattern in cover_patterns:
                    cover_path = video_dir / pattern
                    if cover_path.exists():
                        log(f'  ✅ 找到封面图: {cover_path.name}')
                        try:
                            video_frame_url = upload_video_cover(str(cover_path), image_oss_info, context, log=log)
                            if video_frame_url:
                                log(f'  封面图上传成功: {video_frame_url[:80]}...')
                                break
                            else:
                                log(f'  ⚠️ 封面图上传失败，将尝试提取第一帧')
                        except Exception as e:
                            log(f'  ⚠️ 封面图上传异常: {e}，将尝试提取第一帧')

                # 同基础名图片作为封面（如 视频 xxx-1.mp4 → 封面 xxx-2.jpeg）
                if not video_frame_url:
                    video_base = re.sub(r'[-_]\d+$', '', video_stem)
                    if video_base and video_base != video_stem:
                        for img in sorted(video_dir.glob('*'), key=natural_sort_key):
                            if img.is_file() and img.suffix.lower() in ('.jpg', '.jpeg', '.png', '.webp', '.bmp'):
                                img_stem = img.stem
                                if img_stem.startswith(video_base) and img_stem != video_stem:
                                    log(f'  ✅ 找到同命名封面图: {img.name}')
                                    try:
                                        video_frame_url = upload_image_to_oss(str(img), oss_info, context, log=log)
                                        if video_frame_url:
                                            log(f'  封面图上传成功: {video_frame_url[:80]}...')
                                        else:
                                            log(f'  ⚠️ 封面图上传失败，将尝试提取第一帧')
                                    except Exception as e:
                                        log(f'  ⚠️ 封面图上传异常: {e}，将尝试提取第一帧')
                                    break
                
                if not video_frame_url:
                    # 自动提取视频第一帧
                    log(f'  自动提取视频第一帧作为封面...')
                    frame_path = extract_video_frame(video_path)
                    if frame_path and Path(frame_path).exists():
                        video_frame_url = upload_image_to_oss(frame_path, oss_info, context, log=log)
                        log(f'  视频封面提取成功')
                    else:
                        log(f'  视频封面提取失败（需安装ffmpeg），将使用视频默认封面')
                
                # 生成标题（AI生成或模板）
                random_delay(1000, 2000)
                product_info = extract_product_info_from_path(task.get('dir', video_path))
                product_info['gender'] = state.ai_config.get('gender', 'neutral')
                if state.ai_config.get('category') and state.ai_config['category'] != 'auto':
                    product_info['category'] = state.ai_config['category']
                
                title = generate_video_title(product_info)
                log(f'  生成标题: {title}')
                
                # 文案（视频动态文案可以简短一些）
                content = f'{title}\n\n好物分享，真实测评，喜欢的朋友可以参考一下～'
                
                # 话题
                topics = f'#好物分享 #开箱测评 #{product_info.get("category", "服饰")} #日常穿搭'
                
                # 构建关联商品标签
                product_content_tags = ""
                if product_id:
                    try:
                        product_content_tags = build_product_content_tags([product_id])
                        log(f'  关联好物商品ID: {product_id}')
                    except Exception as e:
                        log(f'  构建关联商品标签失败: {e}')
                
                # 发布视频动态
                random_delay(1500, 2500)
                log(f'  提交视频发布...')
                log(f'  视频参数: url={video_url[:70]}... frame={video_frame_url[:70]}... band={video_band_info}')
                result = publish_trend(
                    title=title,
                    content=content,
                    topics=topics,
                    images_payload="",
                    context=context,
                    product_content_tags=product_content_tags,
                    video_url=video_url,
                    video_frame=video_frame_url,
                    video_band_info=video_band_info,
                )

                if result.success:
                    task['status'] = 'success'
                    task['status_text'] = '发布成功'
                    task['article_url'] = result.article_url
                    log(f'  视频发布成功! contentId={result.content_id}')
                else:
                    # 打印完整响应，便于定位参数问题
                    log(f'  发布失败完整响应: {result.response_text[:800]}')
                    # 检测是否是"操作过快"限流错误
                    fail_msg = result.message or ''
                    if '操作过快' in fail_msg or '20101016' in fail_msg:
                        log(f'  触发得物限流（操作过快），等待60秒后自动重试...')
                        time.sleep(60)
                        log(f'  正在重试发布...')
                        result = publish_trend(
                            title=title,
                            content=content,
                            topics=topics,
                            images_payload="",
                            context=context,
                            product_content_tags=product_content_tags,
                            video_url=video_url,
                            video_frame=video_frame_url,
                            video_band_info=video_band_info,
                        )
                        if result.success:
                            task['status'] = 'success'
                            task['status_text'] = '发布成功'
                            task['article_url'] = result.article_url
                            log(f'  重试发布成功! contentId={result.content_id}')
                        else:
                            task['status'] = 'failed'
                            task['status_text'] = '发布失败'
                            log(f'  重试后仍失败: {result.message}')
                    else:
                        task['status'] = 'failed'
                        task['status_text'] = '发布失败'
                        log(f'  视频发布失败: {result.message}')

            except Exception as e:
                task['status'] = 'failed'
                task['status_text'] = '发布失败'
                log(f'  视频发布异常: {e}\n{traceback.format_exc()}')

            # 发布间隔
            if i < len(state.video_tasks) - 1:
                import random
                if interval_minutes > 0:
                    random_delay_sec = random.randint(0, 30)
                    total_wait = interval_minutes * 60 + random_delay_sec
                    log(f'  等待 {interval_minutes}分{random_delay_sec}秒后发布下一个视频（共{total_wait}秒）...')
                    time.sleep(total_wait)
                else:
                    default_wait = random.randint(30, 60)
                    log(f'  默认等待 {default_wait} 秒后发布下一个视频...')
                    time.sleep(default_wait)

        log(f'视频发布任务完成!')
    except Exception as e:
        if '401 Client Error' in str(e):
            log(f'视频发布任务异常: token 已失效（登录过期），请重新登录后再发布')
            log(f'  详情: {e}')
        else:
            log(f'视频发布任务异常: {e}\n{traceback.format_exc()}')
    finally:
        state.video_publish_running = False


# ==================== 视频发布API ====================
@bp.route('/api/scan_videos', methods=['POST'])
def api_scan_videos():
    data = request.json
    dir_path = data.get('dir', '')
    if not dir_path:
        return jsonify({'success': False, 'message': '请输入视频根目录'})
    if not Path(dir_path).exists():
        return jsonify({'success': False, 'message': '目录不存在'})
    
    state.video_tasks = scan_videos(dir_path)
    log(f'扫描视频完成，共找到 {len(state.video_tasks)} 个视频任务')
    return jsonify({'success': True, 'count': len(state.video_tasks)})


@bp.route('/api/video_tasks', methods=['GET'])
def api_video_tasks():
    stats = {
        'total': len(state.video_tasks),
        'success': sum(1 for t in state.video_tasks if t['status'] == 'success'),
        'failed': sum(1 for t in state.video_tasks if t['status'] == 'failed'),
        'pending': sum(1 for t in state.video_tasks if t['status'] == 'pending'),
    }
    return jsonify({'tasks': state.video_tasks, 'stats': stats})


@bp.route('/api/start_video_publish', methods=['POST'])
def api_start_video_publish():
    if state.video_publish_running:
        return jsonify({'success': False, 'message': '视频发布任务正在进行中'})
    if not state.video_tasks:
        return jsonify({'success': False, 'message': '请先扫描视频'})
    if not state.current_account:
        return jsonify({'success': False, 'message': '请先登录得物账号'})
    # current_account 存在但 token 已被退出登录清除 → 提示重新登录而非发布 401
    if not state.accounts.get(state.current_account, {}).get('token'):
        return jsonify({'success': False, 'message': f'账号 {state.current_account} 无有效token，请重新登录'})
    
    data = request.json
    product_id = data.get('product_id', '')
    interval_minutes = float(data.get('interval_minutes', 0) or 0)
    cover_image = data.get('cover_image', '').strip()

    state.video_publish_running = True
    thread = threading.Thread(
        target=video_publish_worker,
        args=(product_id, interval_minutes, cover_image),
        daemon=True,
    )
    thread.start()
    log(f'视频发布任务已启动，共 {len(state.video_tasks)} 个视频')
    return jsonify({'success': True})


@bp.route('/api/stop_video_publish', methods=['POST'])
def api_stop_video_publish():
    state.video_publish_running = False
    log('用户请求停止视频发布')
    return jsonify({'success': True})


@bp.route('/api/clear_video_tasks', methods=['POST'])
def api_clear_video_tasks():
    state.video_tasks = []
    log('清空视频任务列表')
    return jsonify({'success': True})
