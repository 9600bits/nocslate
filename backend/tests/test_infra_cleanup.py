import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.infra_store import OpsStore
from app.main import app
from app.infra_api import router as infra_router
from app.network_planner import plan_subnets


def test_legacy_kubernetes_records_are_purged(tmp_path):
    path = tmp_path / "ops.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE credential (
          id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT, secret_blob TEXT,
          metadata_json TEXT DEFAULT '{}', created_at TEXT, updated_at TEXT, last_used_at TEXT
        );
        CREATE TABLE cluster_profile (id INTEGER PRIMARY KEY, name TEXT);
    """)
    conn.execute("INSERT INTO credential VALUES (1,'old-kube','kubeconfig','blob','{}','now','now',NULL)")
    conn.commit()
    conn.close()

    # OpsStore creates the current schema and performs the one-way cleanup.
    store = OpsStore(path)
    tables = {row["name"] for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "cluster_profile" not in tables
    assert store.query("SELECT * FROM credential WHERE kind='kubeconfig'") == []
    store.close()


def test_new_api_rejects_removed_kubernetes_types():
    client = TestClient(app)
    response = client.post("/api/vault/credentials", json={
        "name": "should-fail", "kind": "kubeconfig", "secret": "x",
    })
    assert response.status_code == 422
    response = client.post("/api/diagnostics/plans", json={
        "target": "example.com", "target_type": "k8s",
    })
    assert response.status_code == 422


def test_kubernetes_routes_are_removed():
    client = TestClient(app)
    assert client.get("/api/k8s/clusters").status_code == 404


def test_vlsm_planner_supports_auto_and_explicit_masks():
    result = plan_subnets("10.20.0.0/16", [
        {"name": "users", "vlan": 10, "hosts": 500, "prefix": "auto"},
        {"name": "servers", "vlan": 20, "hosts": 100, "prefix": 25},
    ])
    assert result["base_cidr"] == "10.20.0.0/16"
    assert [item["cidr"] for item in result["subnets"]] == ["10.20.0.0/23", "10.20.2.0/25"]
    assert result["subnets"][0]["gateway"] == "10.20.0.1"


def test_network_api_rejects_out_of_range_mask_and_duplicate_vlan():
    client = TestClient(app)
    response = client.post("/api/network/plans", json={
        "name": "bad", "base_cidr": "10.0.0.0/7",
        "requirements": [{"name": "a", "vlan": 10, "hosts": 2}],
    })
    assert response.status_code == 400


def test_network_ai_draft_requires_prompt_and_has_dedicated_routes():
    client = TestClient(app)
    response = client.post("/api/network/plans/ai-draft/preview", json={"prompt": ""})
    assert response.status_code == 422
    paths = {route.path for route in infra_router.routes if hasattr(route, "path")}
    assert "/api/network/plans/ai-draft/preview" in paths
    assert "/api/network/plans/ai-draft/confirm" in paths
    response = client.post("/api/network/plans", json={
        "name": "bad", "base_cidr": "10.0.0.0/16",
        "requirements": [
            {"name": "a", "vlan": 10, "hosts": 2},
            {"name": "b", "vlan": 10, "hosts": 2},
        ],
    })
    assert response.status_code == 400
