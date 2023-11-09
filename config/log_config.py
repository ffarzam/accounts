from datetime import datetime

# import orjson
import pytz
import structlog
import logging.config

from config.config import get_settings

settings = get_settings()


# def dumps(*a, **kw) -> str:
#     return orjson.dumps(*a, **kw).decode()


def configure_logging():
    def timesetter(_, __, event_dict):
        tz = pytz.timezone("Asia/Tehran")
        event_dict["timestamp"] = datetime.now(tz).isoformat()
        return event_dict

    structlog.configure(
        processors=[
            timesetter,
            structlog.processors.add_log_level,
            # structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.format_exc_info,
            # structlog.processors.JSONRenderer(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.AsyncBoundLogger,
        cache_logger_on_first_use=True
    )

    loging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": structlog.processors.JSONRenderer(),
                "foreign_pre_chain": [structlog.stdlib.add_log_level,
                                      structlog.processors.StackInfoRenderer(),
                                      structlog.processors.format_exc_info,
                                      structlog.dev.set_exc_info, ]
            },
        },

        'handlers': {
            'elasticsearch_handler': {
                'level': 'INFO',
                'class': 'config.elastic_log_handler.ElasticsearchHandler',
                'host': settings.ELASTIC_HOST,
                'port': settings.ELASTIC_PORT,
                "formatter": "json"
            },
            'console': {
                'level': 'INFO',
                'class': 'logging.StreamHandler',
            },
        },
        "loggers": {
            "elastic_logger": {
                "handlers": ["elasticsearch_handler"],
                "level": "INFO",
                'propagate': False
            },
            "celery": {
                "handlers": ["console"],
                "level": "INFO",
                'propagate': False
            },

        },

    }
    logging.config.dictConfig(loging_config)
