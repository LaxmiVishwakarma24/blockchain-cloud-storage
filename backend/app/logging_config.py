import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "user": getattr(record, "user", None),
            "action": getattr(record, "action", None),
            "file": getattr(record, "file", None),
            "status": getattr(record, "status", None),
            "request_id": getattr(record, "request_id", None),
        }
        return json.dumps(entry)


def setup_logging(app):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    app.logger.handlers = [handler]
    app.logger.setLevel(logging.INFO)