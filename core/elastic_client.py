import json
import logging
from datetime import datetime, timezone
from typing import Optional

from elasticsearch import Elasticsearch, helpers
from config.settings import settings

logger = logging.getLogger(__name__)


class ElasticClient:
    def __init__(self):
        self.client = None
        self._connect()

    def _connect(self):
        try:
            if settings.ES_CLOUD_ID and settings.ES_API_KEY:
                self.client = Elasticsearch(
                    cloud_id=settings.ES_CLOUD_ID,
                    api_key=(settings.ES_API_KEY_ID, settings.ES_API_KEY),
                    request_timeout=30,
                )
            elif settings.ES_CLOUD_ID:
                self.client = Elasticsearch(
                    cloud_id=settings.ES_CLOUD_ID,
                    basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD),
                    request_timeout=30,
                )
            else:
                self.client = Elasticsearch(
                    settings.ES_HOST,
                    basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD) if settings.ES_PASSWORD else None,
                    verify_certs=False,
                    request_timeout=30,
                )
            info = self.client.info()
            logger.info(f"Connected to Elasticsearch: {info['version']['number']}")
        except Exception as e:
            logger.warning(f"Elasticsearch not available: {e}")
            self.client = None

    @property
    def available(self):
        return self.client is not None

    def index_event(self, event_type: str, body: dict) -> Optional[str]:
        if not self.available:
            logger.debug("ES unavailable, skipping index")
            return None
        try:
            index_name = f"{settings.ES_INDEX_PREFIX}-{event_type}-{datetime.now():%Y.%m.%d}"
            resp = self.client.index(index=index_name, document={
                **body,
                "@timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return resp["_id"]
        except Exception as e:
            logger.error(f"ES index error: {e}")
            return None

    def bulk_index(self, event_type: str, documents: list[dict]) -> int:
        if not self.available or not documents:
            return 0
        try:
            index_name = f"{settings.ES_INDEX_PREFIX}-{event_type}-{datetime.now():%Y.%m.%d}"
            actions = [
                {
                    "_index": index_name,
                    "_source": {
                        **doc,
                        "@timestamp": doc.get("@timestamp", datetime.now(timezone.utc).isoformat()),
                    },
                }
                for doc in documents
            ]
            success, _ = helpers.bulk(self.client, actions, raise_on_error=False)
            return success
        except Exception as e:
            logger.error(f"ES bulk index error: {e}")
            return 0

    def search(self, index_pattern: str, query: dict, size: int = 50) -> list:
        if not self.available:
            return []
        try:
            resp = self.client.search(
                index=f"{settings.ES_INDEX_PREFIX}-{index_pattern}*",
                body={"query": query, "size": size, "sort": [{"@timestamp": "desc"}]},
            )
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as e:
            logger.error(f"ES search error: {e}")
            return []

    def get_stats(self) -> dict:
        if not self.available:
            return {"available": False}
        try:
            critical = self.client.count(
                index=f"{settings.ES_INDEX_PREFIX}-falco-event*",
                body={"query": {"term": {"priority": "CRITICAL"}}},
            )
            total = self.client.count(index=f"{settings.ES_INDEX_PREFIX}-*")
            return {
                "available": True,
                "total_events": total["count"],
                "critical_events": critical["count"],
            }
        except Exception as e:
            return {"available": False, "error": str(e)}
