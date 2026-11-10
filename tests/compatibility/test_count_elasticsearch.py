"""Opt-in real ES count/PIT check; service absence is a skip, never a count."""

from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

from elasticsearch import Elasticsearch
import pytest

from keep.cel import compile_expression
from keep.cel.compiler import epoch_us
from keep.search import index_mapping
from keep.search.counts import CountReader, CountState

pytestmark = pytest.mark.compatibility


@pytest.fixture
def real_search():
    endpoint = os.environ.get("KEEP_TEST_ELASTICSEARCH_URL")
    if not endpoint:
        pytest.skip("Set KEEP_TEST_ELASTICSEARCH_URL to an isolated real Elasticsearch service")
    ca = os.environ.get("KEEP_TEST_ELASTICSEARCH_CA")
    api_key = os.environ.get("KEEP_TEST_ELASTICSEARCH_API_KEY")
    client = Elasticsearch(
        endpoint,
        request_timeout=10,
        **({"ca_certs": ca} if ca else {}),
        **({"api_key": api_key} if api_key else {}),
    )
    index = "keep-test-counts-" + uuid4().hex
    client.indices.create(index=index, mappings=index_mapping())
    yield client, index
    client.indices.delete(index=index)
    client.close()


def test_real_count_batch_native_parity_and_post_pit_insert(real_search):
    client, index = real_search
    now = datetime(2026, 9, 22, 12, tzinfo=UTC)
    tenant, other = str(uuid4()), str(uuid4())
    documents = [
        {
            "id": str(uuid4()),
            "tenant_id": tenant,
            "deleted": False,
            "suppressed": False,
            "severity": "critical",
            "time_created": epoch_us(now),
        },
        {
            "id": str(uuid4()),
            "tenant_id": tenant,
            "deleted": False,
            "suppressed": False,
            "severity": "warning",
            "time_created": epoch_us(now - timedelta(hours=2)),
        },
        {
            "id": str(uuid4()),
            "tenant_id": tenant,
            "deleted": False,
            "suppressed": True,
            "severity": "critical",
            "time_created": epoch_us(now),
        },
        {
            "id": str(uuid4()),
            "tenant_id": other,
            "deleted": False,
            "suppressed": False,
            "severity": "critical",
            "time_created": epoch_us(now),
        },
        {"id": str(uuid4()), "tenant_id": tenant, "deleted": True},
    ]
    operations = []
    for document in documents:
        operations.extend([{"index": {"_index": index, "_id": document["id"]}}, document])
    assert client.bulk(operations=operations, refresh="wait_for")["errors"] is False
    queries = {
        "all": compile_expression("true"),
        "critical": compile_expression('alert.severity == "critical"'),
        "recent": compile_expression('alert.time_created >= now() - duration("1h")'),
    }
    expected = {}
    for name, expression in queries.items():
        expected[name] = sum(
            expression.evaluate(
                {
                    **doc,
                    "time_created": datetime.fromtimestamp(doc["time_created"] / 1_000_000, UTC),
                },
                now,
            )
            for doc in documents
            if doc["tenant_id"] == tenant and not doc["deleted"] and not doc["suppressed"]
        )

    class InsertAfterPIT:
        def options(self, **kwargs):
            self.connection = client.options(**kwargs)
            return self

        def open_point_in_time(self, **kwargs):
            opened = self.connection.open_point_in_time(**kwargs)
            late = {**documents[0], "id": str(uuid4())}
            client.index(index=index, id=late["id"], document=late, refresh="wait_for")
            return opened

        def msearch(self, **kwargs):
            return self.connection.msearch(**kwargs)

        def close_point_in_time(self, **kwargs):
            return self.connection.close_point_in_time(**kwargs)

    state = CountState("count-test", 5, 5, 0, now.isoformat(), 0, False, "none")
    batch = CountReader(InsertAfterPIT(), index).read(
        queries, tenant, evaluated_at=now, before=state, revalidate=lambda: state
    )
    assert batch.counts == expected == {"all": 2, "critical": 1, "recent": 1}
    # A newly opened PIT sees the late insert, proving the old batch was frozen.
    fresh = CountReader(client, index).read(
        {"all": queries["all"]}, tenant, evaluated_at=now, before=state, revalidate=lambda: state
    )
    assert fresh.counts == {"all": 3}
