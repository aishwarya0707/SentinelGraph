import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app


client = TestClient(app)

@pytest.fixture(autouse=True)
def use_test_database(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinelgraph_test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)
    database.initialize_database()


def submit_login(minute, outcome="failure"):
    return client.post(
        "/events",
        json={
            "event_type": "login",
            "username": "demo_user",
            "source_ip": "192.0.2.25",
            "outcome": outcome,
            "timestamp": (
                f"2026-01-01T12:{minute:02d}:00+00:00"
            ),
        },
    )


def test_four_failures_do_not_create_alert():
    for minute in range(4):
        response = submit_login(minute)
        assert response.status_code == 201

    response = client.get("/alerts")

    assert response.json()["count"] == 0


def test_five_failures_create_alert():
    for minute in range(5):
        response = submit_login(minute)
        assert response.status_code == 201

    response = client.get("/alerts")
    data = response.json()

    assert data["count"] == 1
    assert data["alerts"][0]["rule"] == "repeated_failed_logins"
    assert data["alerts"][0]["failed_attempts"] == 5


def test_successful_logins_do_not_create_alert():
    for minute in range(5):
        response = submit_login(minute, outcome="success")
        assert response.status_code == 201

    response = client.get("/alerts")

    assert response.json()["count"] == 0


def test_failures_outside_window_do_not_create_alert():
    for _ in range(4):
        response = submit_login(0)
        assert response.status_code == 201

    response = submit_login(6)
    assert response.status_code == 201

    response = client.get("/alerts")

    assert response.json()["count"] == 0


def test_sixth_failure_updates_existing_alert():
    for minute in range(6):
        response = submit_login(minute)
        assert response.status_code == 201

    response = client.get("/alerts")
    data = response.json()

    assert data["count"] == 1
    assert data["alerts"][0]["failed_attempts"] == 6

def test_get_existing_alert():
    for minute in range(5):
        response = submit_login(minute)
        assert response.status_code == 201

    alerts = client.get("/alerts").json()["alerts"]
    alert_id = alerts[0]["alert_id"]

    response = client.get(f"/alerts/{alert_id}")

    assert response.status_code == 200
    assert response.json()["rule"] == "repeated_failed_logins"
    assert response.json()["failed_attempts"] == 5


def test_get_nonexistent_alert():
    response = client.get("/alerts/9999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"

def test_update_alert_status():
    for minute in range(5):
        response = submit_login(minute)
        assert response.status_code == 201

    alert_id = client.get("/alerts").json()["alerts"][0]["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}",
        params={"status": "investigating"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


def test_update_nonexistent_alert():
    response = client.patch(
        "/alerts/9999",
        params={"status": "closed"},
    )

    assert response.status_code == 404


def test_invalid_alert_status():
    for minute in range(5):
        submit_login(minute)

    alert_id = client.get("/alerts").json()["alerts"][0]["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}",
        params={"status": "invalid"},
    )

    assert response.status_code == 422

def test_filter_events_by_outcome():
    submit_login(0, outcome="failure")
    submit_login(1, outcome="success")
    submit_login(2, outcome="failure")

    response = client.get("/events?outcome=failure")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert all(
        event["outcome"] == "failure"
        for event in response.json()["events"]
    )


def test_filter_events_by_source_ip():
    submit_login(0, outcome="failure")

    response = client.post(
        "/events",
        json={
            "event_type": "login",
            "username": "another_user",
            "source_ip": "192.0.2.30",
            "outcome": "failure",
            "timestamp": "2026-01-01T12:01:00+00:00",
        },
    )
    assert response.status_code == 201

    response = client.get("/events?source_ip=192.0.2.30")

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["events"][0]["source_ip"] == "192.0.2.30"


def test_event_pagination():
    for minute in range(5):
        submit_login(minute, outcome="success")

    response = client.get("/events?limit=2&offset=1")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert response.json()["total"] == 5
    assert response.json()["limit"] == 2
    assert response.json()["offset"] == 1

def test_valid_source_ip_filter():
    submit_login(0)

    response = client.get(
        "/events",
        params={"source_ip": "192.0.2.25"},
    )

    assert response.status_code == 200
    assert all(
        event["source_ip"] == "192.0.2.25"
        for event in response.json()["events"]
    )


def test_invalid_source_ip_filter():
    response = client.get(
        "/events",
        params={"source_ip": "not-an-ip"},
    )

    assert response.status_code == 422

def test_high_severity_for_eight_failures():
    for _ in range(8):
        submit_login(0)

    alerts = client.get("/alerts").json()["alerts"]

    assert alerts[0]["severity"] == "high"
    assert alerts[0]["failed_attempts"] == 8


def test_critical_severity_for_ten_failures():
    for _ in range(10):
        submit_login(0)

    alerts = client.get("/alerts").json()["alerts"]

    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["failed_attempts"] == 10

def test_filter_alerts_by_severity():
    for _ in range(8):
        submit_login(0)

    response = client.get(
        "/alerts",
        params={"severity": "high"},
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["alerts"][0]["severity"] == "high"


def test_filter_alerts_by_status():
    for minute in range(5):
        submit_login(minute)

    alert_id = client.get("/alerts").json()["alerts"][0]["alert_id"]

    update_response = client.patch(
        f"/alerts/{alert_id}",
        params={"status": "investigating"},
    )
    assert update_response.status_code == 200

    response = client.get(
        "/alerts",
        params={"status": "investigating"},
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["alerts"][0]["status"] == "investigating"


def test_invalid_alert_severity_filter():
    response = client.get(
        "/alerts",
        params={"severity": "urgent"},
    )

    assert response.status_code == 422

def test_medium_severity_for_five_failures():
    for _ in range(5):
        submit_login(0)

    alerts = client.get("/alerts").json()["alerts"]

    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["failed_attempts"] == 5

def test_dashboard_summary_empty_database():
    response = client.get("/dashboard/summary")

    assert response.status_code == 200
    data = response.json()

    assert data["total_events"] == 0
    assert data["total_alerts"] == 0
    assert data["open_alerts"] == 0
    assert data["investigating_alerts"] == 0
    assert data["alerts_by_severity"] == {
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def test_dashboard_summary_with_alerts():
    for minute in range(5):
        submit_login(minute)

    response = client.get("/dashboard/summary")

    assert response.status_code == 200
    data = response.json()

    assert data["total_events"] == 5
    assert data["total_alerts"] == 1
    assert data["open_alerts"] == 1
    assert data["investigating_alerts"] == 0
    assert data["alerts_by_severity"]["medium"] == 1

def test_alert_includes_related_failed_login_events():
    for minute in range(5):
        response = submit_login(minute)
        assert response.status_code == 201

    alerts = client.get("/alerts").json()["alerts"]
    alert_id = alerts[0]["alert_id"]

    response = client.get(f"/alerts/{alert_id}")

    assert response.status_code == 200

    data = response.json()
    assert data["rule"] == "repeated_failed_logins"
    assert len(data["related_events"]) == 5
    assert all(
        event["outcome"] == "failure"
        for event in data["related_events"]
    )

def test_multiple_accounts_from_single_ip_creates_alert():
    for i in range(5):
        response = client.post(
            "/events",
            json={
                "event_type": "login",
                "username": f"user_{i}",
                "source_ip": "192.0.2.50",
                "outcome": "failure",
                "timestamp": "2026-01-01T12:00:00+00:00",
            },
        )
        assert response.status_code == 201

    alerts = client.get("/alerts").json()["alerts"]

    matching_alerts = [
        alert for alert in alerts
        if alert["rule"] == "multiple_accounts_from_single_ip"
    ]

    assert len(matching_alerts) == 1
    assert matching_alerts[0]["severity"] == "medium"


def test_three_distinct_usernames_do_not_trigger_new_rule():
    for i in range(3):
        response = client.post(
            "/events",
            json={
                "event_type": "login",
                "username": f"user_{i}",
                "source_ip": "192.0.2.50",
                "outcome": "failure",
                "timestamp": "2026-01-01T12:00:00+00:00",
            },
        )
        assert response.status_code == 201

    alerts = client.get("/alerts").json()["alerts"]

    matching_alerts = [
        alert for alert in alerts
        if alert["rule"] == "multiple_accounts_from_single_ip"
    ]

    assert len(matching_alerts) == 0

def test_brute_force_scenario():
    response = client.post(
        "/lab/scenarios",
        json={"scenario": "brute_force"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["events_submitted"] == 10
    assert any(
        alert["severity"] == "critical"
        for alert in data["alerts"]
        if alert["rule"] == "repeated_failed_logins"
    )


def test_password_spraying_scenario():
    response = client.post(
        "/lab/scenarios",
        json={"scenario": "password_spraying"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["events_submitted"] == 5
    assert any(
        alert["rule"] == "multiple_accounts_from_single_ip"
        for alert in data["alerts"]
    )

def test_successful_logins_across_distinct_users_do_not_trigger_alert():
    usernames = ["alice", "bob", "charlie", "david", "emma"]

    for username in usernames:
        response = client.post(
            "/events",
            json={
                "event_type": "login",
                "username": username,
                "source_ip": "203.0.113.75",
                "outcome": "success",
                "timestamp": "2026-01-01T12:00:00+00:00",
            },
        )
        assert response.status_code == 201

    alerts_response = client.get("/alerts")
    assert alerts_response.status_code == 200
    assert alerts_response.json()["alerts"] == []


def test_normal_activity_scenario():
    response = client.post(
        "/lab/scenarios",
        json={"scenario": "normal_activity"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["events_submitted"] == 5
    assert data["alerts"] == []

def test_failed_logins_outside_five_minute_window_do_not_trigger_alert():
    timestamps = [
        "2026-01-01T12:00:00+00:00",
        "2026-01-01T12:01:00+00:00",
        "2026-01-01T12:02:00+00:00",
        "2026-01-01T12:03:00+00:00",
        "2026-01-01T12:06:00+00:00",
    ]

    for timestamp in timestamps:
        response = client.post(
            "/events",
            json={
                "event_type": "login",
                "username": "demo_user",
                "source_ip": "192.0.2.80",
                "outcome": "failure",
                "timestamp": timestamp,
            },
        )
        assert response.status_code == 201

    alerts_response = client.get("/alerts")
    assert alerts_response.status_code == 200
    assert alerts_response.json()["alerts"] == []



def test_repeated_failed_logins_escalate_severity():
    timestamps = [
        f"2026-01-01T12:00:{second:02d}+00:00"
        for second in range(10)
    ]

    for timestamp in timestamps:
        response = client.post(
            "/events",
            json={
                "event_type": "login",
                "username": "demo_user",
                "source_ip": "192.0.2.90",
                "outcome": "failure",
                "timestamp": timestamp,
            },
        )
        assert response.status_code == 201

    alerts_response = client.get(
        "/alerts",
        params={"status": "open"},
    )
    assert alerts_response.status_code == 200

    alerts = alerts_response.json()["alerts"]
    brute_force_alerts = [
        alert for alert in alerts
        if alert["rule"] == "repeated_failed_logins"
        and alert["source_ip"] == "192.0.2.90"
    ]

    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0]["failed_attempts"] == 10
    assert brute_force_alerts[0]["severity"] == "critical"
