# services/jobs.py
from common.celery_client import celery_client
from common.config import TASK_RUN_FETCH_AND_RECO

def enqueue_fetch_and_reco():
    """Queue the wrapper task that runs fetch -> reco."""
    return celery_client.send_task(TASK_RUN_FETCH_AND_RECO)

def get_task_status(task_id: str):
    """Simple status lookup."""
    async_res = celery_client.AsyncResult(task_id)
    return {
        "id": task_id,
        "state": async_res.state,
        "ready": async_res.ready(),
        "successful": async_res.successful() if async_res.ready() else None,
        "result": async_res.result if async_res.ready() else None,
    }
