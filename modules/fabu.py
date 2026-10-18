"""图文发布模块：图片扫描分组、任务列表、图文发布工作线程

由 dewu_web.py 拆分而来，通过蓝图提供 /api/scan_images、/api/tasks、
/api/start_publish、/api/stop_publish、/api/clear_tasks。
"""
import json
import threading
import time
import traceback
from pathlib import Path

from flask import Blueprint, jsonify, request

from dewu_api import (
    DewuContext,
    get_oss_info,
    upload_image_to_oss,
    build_images_payload,
    build_product_content_tags,
    publish_trend,
)
from modules.cunchu import state
from modules.gongju import natural_sort_key, random_delay
from modules.rizhi import log
from modules.shengcheng import (
    extract_product_info_from_path,
    generate_unique_content,
    get_product_key,
    reset_used_content,
)

bp = Blueprint('fabu', __name__)


@bp.route('/api/scan_images', methods=['POST'])
def api_scan_images():
    data = request.json
    dir_path = data.get('dir', '').strip()
    if not dir_path:
        return jsonify({'success': False, 'message': '目录不能为空'})
    try:
        root = Path(dir_path)
        if not root.exists() or not root.is_dir():
            return jsonify({'success': False, 'message': '目录不存在'})

        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        group_size = int(data.get('group_size', 0) or 0)
        tasks = []

        # 收集所有图片
        all_images = []
        for img in sorted(root.rglob('*'), key=natural_sort_key):
            if img.is_file() and img.suffix.lower() in image_exts:
                all_images.append(str(img))

        if group_size > 0:
            # 按指定数量分组
            group_size = min(group_size, 9)  # 最多9张
            for i in range(0, len(all_images), group_size):
                group_images = all_images[i:i+group_size]
                group_num = i // group_size + 1
                tasks.append({
                    'title': f'第{group_num}组',
                    'dir': str(root),
                    'images': group_images,
                    'image_count': len(group_images),
                    'status': 'pending',
                    'status_text': '待发布',
                    'article_url': '',
                })
        else:
            # 按文件夹分组（原有逻辑）
            for child in sorted(root.iterdir()):
                if child.is_dir():
                    images = []
                    for img in sorted(child.rglob('*'), key=natural_sort_key):
                        if img.is_file() and img.suffix.lower() in image_exts:
                            images.append(str(img))
                    if images:
                        tasks.append({
                            'title': child.name,
                            'dir': str(child),
                            'images': images,
                            'image_count': len(images),
                            'status': 'pending',
                            'status_text': '待发布',
                            'article_url': '',
                        })

            # 如果没有子文件夹，扫描根目录下的图片
            if not tasks:
                if all_images:
                    tasks.append({
                        'title': root.name,
                        'dir': str(root),
                        'images': all_images,
                        'image_count': len(all_images),
                        'status': 'pending',
                        'status_text': '待发布',
                        'article_url': '',
                    })

        state.publish_tasks = tasks
        if group_size > 0:
            log(f'扫描图片完成: 共 {len(all_images)} 张图片，按每组{group_size}张分为 {len(tasks)} 组')
        else:
            log(f'扫描图片完成: 共 {len(tasks)} 个文件夹')
        return jsonify({'success': True, 'count': len(tasks)})
    except Exception as e:
        log(f'扫描图片失败: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': str(e)})


@bp.route('/api/tasks')
def api_tasks():
    stats = {'total': len(state.publish_tasks), 'success': 0, 'failed': 0, 'pending': 0}
    for t in state.publish_tasks:
        if t['status'] == 'success':
            stats['success'] += 1
        elif t['status'] == 'failed':
            stats['failed'] += 1
        else:
            stats['pending'] += 1
    return jsonify({'tasks': state.publish_tasks, 'stats': stats})


@bp.route('/api/start_publish', methods=['POST'])
def api_start_publish():
    if state.publish_running:
        return jsonify({'success': False, 'message': '发布任务正在运行中'})
    if not state.current_account:
        return jsonify({'success': False, 'message': '请先登录账号'})
    # current_account 存在但 token 已被退出登录清除 → 提示重新登录而非发布 401
    if not state.accounts.get(state.current_account, {}).get('token'):
        return jsonify({'success': False, 'message': f'账号 {state.current_account} 无有效token，请重新登录'})
    if not state.publish_tasks:
        return jsonify({'success': False, 'message': '请先扫描图片'})

    data = request.json
    default_title = data.get('title', '')
    default_content = data.get('content', '')
    default_topics = data.get('topics', '')
    product_id = data.get('product_id', '').strip()
    interval_minutes = float(data.get('interval_minutes', 0) or 0)
    auto_generate_each = data.get('auto_generate_each', True)

    state.publish_running = True
    thread = threading.Thread(
        target=publish_worker,
        args=(default_title, default_content, default_topics, product_id, interval_minutes, auto_generate_each),
        daemon=True,
    )
    thread.start()
    return jsonify({'success': True})


def publish_worker(default_title, default_content, default_topics, product_id="", interval_minutes=0, auto_generate_each=True):
    """发布工作线程"""
    try:
        account_info = state.accounts.get(state.current_account, {})
        context = DewuContext(
            token=account_info.get('token', ''),
            user_id=account_info.get('user_id', ''),
            user_name=account_info.get('user_name', ''),
            login_token=account_info.get('login_token', ''),
        )

        log(f'开始发布任务，账号: {state.current_account}')
        log(f'获取OSS上传信息...')
        oss_info = get_oss_info(context)
        log(f'OSS信息获取成功')
        random_delay(1000, 2000)  # 随机抖动

        for i, task in enumerate(state.publish_tasks):
            if not state.publish_running:
                log(f'发布任务已停止')
                break

            if task['status'] == 'success':
                continue

            task['status'] = 'running'
            task['status_text'] = '发布中'
            log(f'[{i+1}/{len(state.publish_tasks)}] 正在发布: {task["title"]} ({task["image_count"]}张图片)')

            try:
                # 上传图片
                image_urls = []
                for j, img_path in enumerate(task['images'][:9]):  # 最多9张
                    random_delay(1000, 2000)  # 上传前随机抖动
                    log(f'  上传图片 {j+1}/{min(len(task["images"]), 9)}: {Path(img_path).name}')
                    url = upload_image_to_oss(img_path, oss_info, context, log=log)
                    image_urls.append(url)
                    random_delay(500, 1500)  # 上传后随机抖动

                # 构建发布参数
                random_delay(1000, 2000)  # 生成内容前随机抖动
                if auto_generate_each:
                    # 每组自动生成不同的标题和文案（即使填了默认内容也会生成不同的）
                    product_info = extract_product_info_from_path(task.get('dir', task.get('images', [''])[0] if task.get('images') else ''))
                    # 从AI设置中获取目标人群和品类（使用全局变量ai_config）
                    product_info['gender'] = state.ai_config.get('gender', 'neutral')
                    if state.ai_config.get('category') and state.ai_config['category'] != 'auto':
                        product_info['category'] = state.ai_config['category']
                    
                    # 生成内容（持久化去重，考虑历史已使用的内容，确保多次发布也不重复）
                    product_key = get_product_key(task.get('dir', task.get('images', [''])[0] if task.get('images') else ''))
                    
                    # 优化：如果第一组用户已手动生成内容，不重复调用AI（避免二次调用浪费token）
                    if i == 0 and (default_title or default_content):
                        title = default_title
                        content = default_content
                        topics = default_topics or ''
                        log(f'  使用用户手动生成的内容（第一组，不重复调用AI）')
                    else:
                        # 取第一张图片用于AI识别
                        first_image = None
                        if task.get('images') and len(task['images']) > 0:
                            first_image = task['images'][0]
                        generated = generate_unique_content(product_info, product_key, image_path=first_image)
                        title = generated['title']
                        content = generated['content']
                        topics = generated['topics']
                        log(f'  自动生成标题: {title}')
                        log(f'  自动生成文案: {content[:50]}...')
                    
                    # 标题和文案已在generate_unique_content中记录到持久化文件
                else:
                    # 不自动生成，所有组使用默认内容（或固定模板）
                    title = default_title or task['title']
                    content = default_content or f'{task["title"]} 好物分享，日常穿搭记录。'
                    topics = default_topics
                    log(f'  使用统一内容')

                random_delay(1000, 2000)  # 构建发布参数前随机抖动
                images_payload = build_images_payload(image_urls)

                # 构建关联商品标签
                product_content_tags = ""
                if product_id:
                    try:
                        product_content_tags = build_product_content_tags([product_id])
                        log(f'  关联好物商品ID: {product_id}')
                    except Exception as e:
                        log(f'  构建关联商品标签失败: {e}')

                # 发布
                random_delay(1500, 2500)  # 提交发布前随机抖动（稍长一点）
                log(f'  提交发布...')
                result = publish_trend(
                    title=title,
                    content=content,
                    topics=topics,
                    images_payload=images_payload,
                    context=context,
                    product_content_tags=product_content_tags,
                )

                random_delay(1000, 2000)  # 发布结果处理前随机抖动
                if result.success:
                    task['status'] = 'success'
                    task['status_text'] = '发布成功'
                    task['article_url'] = result.article_url
                    log(f'  发布成功! contentId={result.content_id}')
                else:
                    # 检测是否是"操作过快"限流错误，如果是则自动等待后重试
                    fail_msg = result.message or ''
                    if '操作过快' in fail_msg or '20101016' in fail_msg or '频繁' in fail_msg:
                        log(f'  触发得物限流（操作过快），等待60秒后自动重试...')
                        time.sleep(60)
                        # 重试一次
                        log(f'  正在重试发布...')
                        result = publish_trend(
                            title=title,
                            content=content,
                            topics=topics,
                            images_payload=images_payload,
                            context=context,
                            product_content_tags=product_content_tags,
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
                        log(f'  发布失败: {result.message}')

            except Exception as e:
                task['status'] = 'failed'
                task['status_text'] = '发布失败'
                log(f'  发布异常: {e}\n{traceback.format_exc()}')

            # 发布间隔：用户设置的间隔 + 随机延迟（避免规律性发布触发限流）
            import random
            if interval_minutes > 0:
                # 用户设置了间隔，在基础上增加0-30秒随机延迟
                random_extra_seconds = random.randint(0, 30)
                total_wait = interval_minutes * 60 + random_extra_seconds
                log(f'  等待 {interval_minutes}分{random_extra_seconds}秒后发布下一组（共{total_wait}秒，含随机延迟）...')
                time.sleep(total_wait)
            else:
                # 默认间隔：30-60秒随机（避免发布太快触发限流）
                default_wait = random.randint(30, 60)
                log(f'  默认等待 {default_wait} 秒后发布下一组（避免操作过快）...')
                time.sleep(default_wait)

        log(f'发布任务完成!')
    except Exception as e:
        if '401 Client Error' in str(e):
            log(f'发布任务异常: token 已失效（登录过期），请重新登录后再发布')
            log(f'  详情: {e}')
        else:
            log(f'发布任务异常: {e}\n{traceback.format_exc()}')
    finally:
        state.publish_running = False


@bp.route('/api/stop_publish', methods=['POST'])
def api_stop_publish():
    state.publish_running = False
    log('用户请求停止发布')
    return jsonify({'success': True})


@bp.route('/api/clear_tasks', methods=['POST'])
def api_clear_tasks():
    # 清空任务时，重置所有单品的已使用内容记录（让用户可以重新开始）
    reset_used_content()
    state.publish_tasks = []
    log('清空任务列表，已使用内容记录已重置')
    return jsonify({'success': True})
