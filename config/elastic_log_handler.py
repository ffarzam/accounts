import json
import logging

import time
from datetime import datetime

from elasticsearch import Elasticsearch


class ElasticsearchHandler(logging.Handler):
    def __init__(self, host, port, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.es = Elasticsearch(f'http://{host}:{port}')
        # self.formatter = formatter

    def emit(self, record):
        self.es.index(index=self.get_index_name(), document=record.msg)

    @staticmethod
    def get_index_name():
        return f'log_{time.strftime("%Y_%m_%d")}'
