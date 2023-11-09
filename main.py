import time
import traceback
from uuid import uuid4
import structlog
import uvicorn

from fastapi import FastAPI, Request, Response

from api.v1.accounts import routers as accounts_router
from config.config import get_settings
from config.log_config import configure_logging


app = FastAPI()

settings = get_settings()

configure_logging()
logger = structlog.get_logger("elastic_logger")


@app.middleware("http")
async def logger_middleware(request: Request, call_next):
    unique_id = request.headers.get("unique_id")
    if not unique_id:
        unique_id = uuid4().hex
    setattr(request.state, "unique_id", unique_id)

    log_entry = {
        "request_path": request.url.path,
        "unique_id": unique_id,
        "request_method": request.method,
        'request_ip': request.client.host or ' ',
        'request_user_agent': request.headers.get('user-agent', ' '),
    }
    bind_log = logger.bind(**log_entry)
    response = Response("some error happened", status_code=500)
    try:
        start_time = time.perf_counter_ns()
        response = await call_next(request)
        end_time = time.perf_counter_ns()
        process_time = end_time - start_time
    except Exception as e:
        exception_log_entry = {
            "response_status": response.status_code,
            'exception_type': e.__class__.__name__,
            'exception_message': str(e),
            'exception_traceback': traceback.format_exc(),
            'exception': True
        }
        await bind_log.critical("account", **exception_log_entry)
        # await bind_log.exception("Notification.exception")
    else:
        extera_log_entry = {
            "response_status": response.status_code,
            "process_time": process_time / (10 ** 9)
        }
        await bind_log.info("account", **extera_log_entry)
    return response


app.include_router(accounts_router, prefix="/accounts")

if __name__ == "__main__":
    uvicorn.run("__main__:app", host="0.0.0.0", port=8002, reload=True)
