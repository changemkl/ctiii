# celery_app.py
import os
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready
from kombu import Queue
# Allow override via env for local dev
BROKER_URL  = os.getenv(
    "CELERY_BROKER_URL",
    "redis://default:FY0eHpAwCj2eRxoTiUcJTn4T8dkmLWGE@redis-14436.c114.us-east-1-4.ec2.redns.redis-cloud.com:14436/0"
)
BACKEND_URL = os.getenv("CELERY_RESULT_BACKEND", BROKER_URL)

celery = Celery(
    "cti",
    broker=BROKER_URL,
    backend=BACKEND_URL,
    include=["worker.tasks"],   # ✅ 确保注册到 worker.tasks.* 的任务都能被发现
)

# celery_app.py
celery.conf.update(
    timezone="Europe/London",
    enable_utc=True,

    # —— 限连接&更稳 —— 
    broker_connection_retry_on_startup=True,
    broker_heartbeat=30,                  # 心跳别太频繁
    broker_pool_limit=2,                  # ★ 关键：限制 broker 连接池
    broker_transport_options={
        "max_connections": 5,             # ★ 关键：Redis 传输连接上限
        "visibility_timeout": 3600,
    },

    # —— 结果后端（如果你不查结果，建议忽略结果） —— 
    result_backend=BACKEND_URL,
    redis_max_connections=2,              # ★ 关键：限制后端连接
    result_expires=300,                   # 结果保留时间
    result_persistent=False,              # 不持久化结果文件
    task_ignore_result=True,              # ★ 全局忽略结果（最省连接）

    # —— Worker 行为 —— 
    worker_prefetch_multiplier=1,         # 每 worker 只预取 1 条，减少占用/堆积
    task_acks_late=True,
)



# --- 定义三个队列：realtime（前台即时）、scheduled（beat）、default（兜底） ---
celery.conf.task_queues = (
    Queue("realtime"),
    Queue("scheduled"),
    Queue("default"),
)
celery.conf.task_default_queue = "default"

# --- 路由：把任务分发到指定队列 ---
celery.conf.task_routes = {
    # 实时：用户点击“添加 RSS”只走这个队列
    "worker.tasks.run_fetch_user_rss_once": {"queue": "realtime"},

    # 定时：全部丢到 scheduled，不挤占实时
    "worker.tasks.run_fetch_all_rss_dedup": {"queue": "scheduled"},
    "worker.tasks.run_fetch": {"queue": "scheduled"},
    "worker.tasks.run_cybok_reco_gridfs": {"queue": "scheduled"},
    "worker.tasks.run_ingest_cybok_intro_pdf": {"queue": "scheduled"},
    "worker.tasks.run_fetch_and_reco": {"queue": "scheduled"},
}



if os.getenv("DISABLE_BEAT", "0") != "1":
    celery.conf.beat_schedule = {
        # 每10分钟：主抓取 + 推荐
        "run-fetch-every-10min": {
            "task": "worker.tasks.run_fetch_and_reco",
            "schedule": 600.0,
        },

        # 每天 03:00：重建 CyBOK 推荐
        "run-reco-gridfs-3am": {
            "task": "worker.tasks.run_cybok_reco_gridfs",
            "schedule": crontab(minute=0, hour=3),
        },

        # ✅ 新增：每小时第 20 分，去重抓取仓库里所有 RSS
        "run-fetch-all-rss-hourly": {
            "task": "worker.tasks.run_fetch_all_rss_dedup",
            "schedule": crontab(minute=20),   # 每小时 xx:20
            "kwargs": {
                "limit": 200,
                # "owner_filter": ["alice","bob"],  # 可选
                # "sample": 50,                     # 可选：仅处理前 N 个 URL
            },
        },
    }
else:
    celery.conf.beat_schedule = {}


@worker_ready.connect
def _kickoff_once(sender, **kwargs):
    """
    worker 启动时“只跑一次”的任务。
    若不想自动跑，把环境变量 RUN_STARTUP_TASKS=0
    """
    if os.getenv("RUN_STARTUP_TASKS", "1") != "1":
        return
    # app = sender.app
    # app.send_task("worker.tasks.run_fetch")
    # app.send_task("worker.tasks.run_ingest_cybok_intro_pdf")  # 若没有实现，可保留我们在 tasks.py 里的占位
    # app.send_task("worker.tasks.run_cybok_reco_gridfs")
