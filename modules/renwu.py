"""多任务队列模块：任务队列调度与发布工作线程

由 dewu_web.py 拆分而来，通过蓝图提供 /api/task_queue 系列接口。
"""
import json
import re
import threading
import time
import traceback
from pathlib import Path

from flask import Blueprint, jsonify, request

from dewu_api import (
    DewuContext,
    get_oss_info,
    upload_image_to_oss,
    build_product_content_tags,
    publish_trend,
)
from modules.cunchu import state
from modules.gongju import natural_sort_key, random_delay
from modules.rizhi import log
from modules.shengcheng import generate_unique_content

bp = Blueprint('renwu', __name__)


@bp.route('/api/task_queue', methods=['GET'])
def api_get_task_queue():
    """获取任务队列"""
    with state.task_queue_lock:
        return jsonify({'success': True, 'tasks': state.task_queue})


@bp.route('/api/add_task', methods=['POST'])
def api_add_task():
    """添加任务到队列"""
    data = request.get_json()
    image_dir = data.get('image_dir', '').strip()
    product_id = data.get('product_id', '').strip()
    images_per_group = int(data.get('images_per_group', 5))
    interval_minutes = float(data.get('interval_minutes', 5))

    if not image_dir or not Path(image_dir).exists():
        return jsonify({'success': False, 'message': '图片文件夹不存在'})

    with state.task_queue_lock:
        task_id = len(state.task_queue) + 1
        task = {
            'id': task_id,
            'image_dir': image_dir,
            'product_id': product_id,
            'images_per_group': images_per_group,
            'interval_minutes': interval_minutes,
            'status': 'pending',  # pending, running, completed, failed
            'progress': '0/0',
            'current_group': 0,
            'total_groups': 0,
            'result': '',
            'logs': []
        }
        state.task_queue.append(task)
    return jsonify({'success': True, 'task': task, 'message': f'任务{task_id}已添加'})


@bp.route('/api/remove_task', methods=['POST'])
def api_remove_task():
    """删除单个任务"""
    data = request.get_json()
    task_id = data.get('task_id')
    with state.task_queue_lock:
        state.task_queue = [t for t in state.task_queue if t['id'] != task_id]
    return jsonify({'success': True, 'message': f'任务{task_id}已删除'})


@bp.route('/api/clear_task_queue', methods=['POST'])
def api_clear_task_queue():
    """清空任务队列"""
    with state.task_queue_lock:
        state.task_queue.clear()
        state.task_queue_running = False
    return jsonify({'success': True, 'message': '任务队列已清空'})


@bp.route('/api/start_all_tasks', methods=['POST'])
def api_start_all_tasks():
    """开始全部任务（自动衔接发布）"""
    with state.task_queue_lock:
        pending_count = sum(1 for t in state.task_queue if t['status'] == 'pending')
        if pending_count == 0:
            return jsonify({'success': False, 'message': '没有待发布的任务'})
        if state.task_queue_running:
            return jsonify({'success': False, 'message': '任务队列正在运行中'})
        state.task_queue_running = True

    # 启动任务队列处理线程
    state.task_queue_thread = threading.Thread(target=task_queue_worker, daemon=True)
    state.task_queue_thread.start()
    return jsonify({'success': True, 'message': f'开始发布{pending_count}个任务'})


def task_queue_worker():
    """任务队列处理线程：依次处理每个任务，自动衔接"""
    log("🚀 任务队列开始运行...")

    while state.task_queue_running:
        # 找到下一个pending状态的任务
        current_task = None
        with state.task_queue_lock:
            for task in state.task_queue:
                if task['status'] == 'pending':
                    current_task = task
                    break

        if not current_task:
            log("✅ 所有任务已完成！")
            state.task_queue_running = False
            break

        task_id = current_task['id']
        image_dir = current_task['image_dir']
        product_id = current_task['product_id']
        images_per_group = current_task['images_per_group']
        interval_minutes = current_task['interval_minutes']

        log(f"\n{'='*60}")
        log(f"📦 开始发布任务 {task_id}")
        log(f"   图片文件夹: {image_dir}")
        log(f"   商品ID: {product_id}")
        log(f"   每组图片数: {images_per_group}")
        log(f"   发布间隔: {interval_minutes}分钟")
        log(f"{'='*60}")

        # 更新任务状态为running
        with state.task_queue_lock:
            for task in state.task_queue:
                if task['id'] == task_id:
                    task['status'] = 'running'
                    break

        try:
            # 扫描图片
            image_files = []
            exts = {'.jpg', '.jpeg', '.png', '.webp', '.bmp'}
            for f in Path(image_dir).iterdir():
                if f.suffix.lower() in exts:
                    image_files.append(str(f))

            # 自然排序（复用模块级 natural_sort_key）
            image_files.sort(key=natural_sort_key)

            total_images = len(image_files)
            if total_images == 0:
                raise Exception("文件夹中没有图片")

            # 计算分组
            total_groups = (total_images + images_per_group - 1) // images_per_group

            with state.task_queue_lock:
                for task in state.task_queue:
                    if task['id'] == task_id:
                        task['total_groups'] = total_groups
                        task['progress'] = f'0/{total_groups}'
                        break

            log(f"📊 扫描到 {total_images} 张图片，分为 {total_groups} 组")

            # 获取当前账号信息并创建DewuContext
            account_info = state.accounts.get(state.current_account, {})
            context = DewuContext(
                token=account_info.get('token', ''),
                user_id=account_info.get('user_id', ''),
                user_name=account_info.get('user_name', ''),
            )
            log(f"使用账号: {state.current_account}")

            # 获取OSS信息
            oss_info = get_oss_info(context)
            if not isinstance(oss_info, dict):
                raise Exception("获取OSS上传信息失败")

            # 依次发布每组
            success_count = 0
            for group_idx in range(total_groups):
                if not state.task_queue_running:
                    log("⏸️ 任务队列已暂停")
                    break

                start_idx = group_idx * images_per_group
                end_idx = min(start_idx + images_per_group, total_images)
                group_images = image_files[start_idx:end_idx]

                log(f"\n[组 {group_idx+1}/{total_groups}] 发布 {len(group_images)} 张图片...")

                # 上传图片
                uploaded_urls = []
                for img_idx, img_path in enumerate(group_images):
                    log(f"  上传图片 {img_idx+1}/{len(group_images)}: {Path(img_path).name}")
                    random_delay(1000, 2000)
                    try:
                        url = upload_image_to_oss(img_path, oss_info, context, log=log)
                        if url:
                            uploaded_urls.append(url)
                    except Exception as e:
                        log(f"  ⚠️ 图片上传失败: {e}")

                if not uploaded_urls:
                    log(f"  ❌ 第{group_idx+1}组图片全部上传失败，跳过")
                    continue

                # 构建images payload
                images_payload = json.dumps([{'url': url, 'type': 1, 'index': i}
                                               for i, url in enumerate(uploaded_urls)], ensure_ascii=False)

                # AI生成内容
                product_info = {
                    'sku': Path(image_dir).name,
                    'color': '',
                    'category': '服饰',
                    'gender': state.ai_config.get('gender', 'neutral'),
                    'category_manual': state.ai_config.get('category', 'auto')
                }
                product_key = f"task_{task_id}_{Path(image_dir).name}"
                first_image = group_images[0] if group_images else None
                generated = generate_unique_content(product_info, product_key, image_path=first_image)

                title = generated['title']
                content_text = generated['content']
                topics = generated['topics']

                log(f"  标题: {title}")
                log(f"  文案: {content_text[:50]}...")

                # 构建关联商品标签
                product_content_tags = ""
                if product_id:
                    try:
                        product_ids = [pid.strip() for pid in re.split(r'[,，\n]', product_id) if pid.strip()]
                        product_content_tags = build_product_content_tags(product_ids)
                        log(f"  关联好物: {len(product_ids)}个商品")
                    except Exception as e:
                        log(f"  ⚠️ 构建关联商品标签失败: {e}")

                # 提交发布
                random_delay(1000, 2000)
                log(f"  提交发布...")
                result = publish_trend(
                    title=title,
                    topics=topics,
                    content=content_text,
                    friend="",
                    product_content_tags=product_content_tags,
                    images_payload=images_payload,
                    context=context,
                    timeout=60
                )

                if result.success:
                    success_count += 1
                    log(f"  ✅ 发布成功！contentId={result.content_id}")
                    log(f"  文章链接: {result.article_url}")
                else:
                    log(f"  ❌ 发布失败: {result.message}")

                # 更新进度
                with state.task_queue_lock:
                    for task in state.task_queue:
                        if task['id'] == task_id:
                            task['current_group'] = group_idx + 1
                            task['progress'] = f'{group_idx+1}/{total_groups}'
                            break

                # 组间等待（最后一组不等）
                if group_idx < total_groups - 1 and state.task_queue_running:
                    wait_seconds = int(interval_minutes * 60)
                    log(f"\n⏰ 等待 {interval_minutes} 分钟后发布下一组...")
                    for s in range(wait_seconds):
                        if not state.task_queue_running:
                            break
                        time.sleep(1)
                    random_delay(1000, 2000)

            # 任务完成
            with state.task_queue_lock:
                for task in state.task_queue:
                    if task['id'] == task_id:
                        task['status'] = 'completed'
                        task['result'] = f'成功{success_count}/{total_groups}组'
                        break

            log(f"\n✅ 任务 {task_id} 完成！成功发布 {success_count}/{total_groups} 组")

        except Exception as e:
            log(f"\n❌ 任务 {task_id} 失败: {e}")
            import traceback
            log(traceback.format_exc())
            with state.task_queue_lock:
                for task in state.task_queue:
                    if task['id'] == task_id:
                        task['status'] = 'failed'
                        task['result'] = str(e)
                        break

        # 任务间等待（最后一个任务不等）
        with state.task_queue_lock:
            remaining = sum(1 for t in state.task_queue if t['status'] == 'pending')
        if remaining > 0 and state.task_queue_running:
            log(f"\n⏰ 等待 10 秒后开始下一个任务...")
            time.sleep(10)

    log("\n🎉 任务队列全部完成！")
    state.task_queue_running = False
