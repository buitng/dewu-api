"""通用工具函数（无业务状态依赖）

包含：自然排序、随机抖动延迟
"""
import random
import re
import time


def random_delay(min_ms=1000, max_ms=2000):
    """随机抖动延迟，模拟真人操作节奏，默认1000-2000ms"""
    delay_ms = random.randint(min_ms, max_ms)
    time.sleep(delay_ms / 1000)
    return delay_ms


def natural_sort_key(path):
    """
    自然排序的key函数
    把字符串中的数字按整数比较，非数字部分按字符串比较
    效果：1.jpg, 2.jpg, ..., 10.jpg, 11.jpg, ..., 100.jpg
    """
    name = str(path)
    # 把字符串分成数字和非数字部分
    parts = re.split(r'(\d+)', name)
    # 数字部分转成整数，非数字部分转成小写字符串
    return [int(part) if part.isdigit() else part.lower() for part in parts]
