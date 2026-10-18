
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, IPvAnyAddress
from pathlib import Path
from fastapi.responses import FileResponse
from app.database import get_connection, initialize_database

app = FastAPI(
    title="SentinelGraph",
    description="Security Event Detection and Investigation Platform",
    version="0.4.0",
)

initialize_database()


class SecurityEvent(BaseModel):
    event_type: Literal["login"]
    username: str
    source_ip: IPvAnyAddress
    outcome: Literal["success", "failure"]
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

class ScenarioRequest(BaseModel):
    scenario: Literal[
        "brute_force",
        "password_spraying",
        "normal_activity",
    ]

@app.get("/")
def home():
    return {
        "project": "SentinelGraph",
        "status": "running",
        "message": "Security monitoring platform is ready",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/events", status_code=201)
def create_event(event: SecurityEvent):
    event_time = event.timestamp

    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    event_time = event_time.astimezone(timezone.utc)

    timestamp = event_time.isoformat(timespec="microseconds")
    source_ip = str(event.source_ip)

    with closing(get_connection()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_events
                (event_type, username, source_ip, outcome, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.event_type,
                event.username,
                source_ip,
                event.outcome,
                timestamp,
            ),
        )

        event_id = cursor.lastrowid
        alert_created = None

        if event.event_type == "login" and event.outcome == "failure":
            window_start = (
                event_time - timedelta(minutes=5)
            ).isoformat(timespec="microseconds")

            matching = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM security_events
                WHERE event_type = 'login'
                  AND outcome = 'failure'
                  AND source_ip = ?
                  AND timestamp >= ?
                  AND timestamp <= ?
                """,
                (source_ip, window_start, timestamp),
            ).fetchone()

            failed_attempts = matching["total"]

            if failed_attempts >= 5:
                if failed_attempts >= 10:
                    severity = "critical"
                elif failed_attempts >= 8:
                    severity = "high"
                else:
                    severity = "medium"
                existing_alert = connection.execute(
                    """
                    SELECT alert_id
                    FROM alerts
                    WHERE rule = 'repeated_failed_logins'
                      AND source_ip = ?
                      AND status = 'open'
                      AND created_at >= ?
                      AND created_at <= ?
                    ORDER BY alert_id DESC
                    LIMIT 1
                    """,
                    (source_ip, window_start, timestamp),
                ).fetchone()

                if existing_alert:
                    alert_id = existing_alert["alert_id"]

                    connection.execute(
                        """
                        UPDATE alerts
                        SET failed_attempts = ?, severity = ?
                        WHERE alert_id = ?
                        """,
                        (failed_attempts, severity, alert_id),
                    )
                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO alerts (
                            rule, severity, source_ip,
                            failed_attempts, window_minutes,
                            status, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "repeated_failed_logins",
                            severity,
                            source_ip,
                            failed_attempts,
                            5,
                            "open",
                            timestamp,
                        ),
                    )
                    alert_id = cursor.lastrowid

                alert_created = {
                    "alert_id": alert_id,
                    "rule": "repeated_failed_logins",
                    "severity": severity,
                    "source_ip": source_ip,
                    "failed_attempts": failed_attempts,
                    "window_minutes": 5,
                    "status": "open",
                }
        additional_alert_created = None

        if event.event_type == "login":
            window_start = (
                event_time - timedelta(minutes=5)
            ).isoformat(timespec="microseconds")

            
            activity = connection.execute(
                """
                SELECT
                    COUNT(
                        DISTINCT CASE
                            WHEN outcome = 'failure' THEN username
                        END
                    ) AS unique_users,
                    SUM(
                        CASE WHEN outcome = 'failure' THEN 1 ELSE 0 END
                    ) AS failed_attempts
                FROM security_events
                WHERE event_type = 'login'
                AND source_ip = ?
                AND timestamp >= ?
                AND timestamp <= ?
                """,
                (source_ip, window_start, timestamp),
            ).fetchone()

            unique_users = activity["unique_users"]
            failed_count = activity["failed_attempts"] or 0

            if unique_users >= 5 and failed_count > 0:
                existing = connection.execute(
                    """
                    SELECT alert_id
                    FROM alerts
                    WHERE rule = 'multiple_accounts_from_single_ip'
                      AND source_ip = ?
                      AND status = 'open'
                      AND created_at >= ?
                      AND created_at <= ?
                    ORDER BY alert_id DESC
                    LIMIT 1
                    """,
                    (source_ip, window_start, timestamp),
                ).fetchone()

                if existing:
                    alert_id = existing["alert_id"]
                    connection.execute(
                        """
                        UPDATE alerts
                        SET failed_attempts = ?
                        WHERE alert_id = ?
                        """,
                        (failed_count, alert_id),
                    )
                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO alerts (
                            rule, severity, source_ip,
                            failed_attempts, window_minutes,
                            status, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "multiple_accounts_from_single_ip",
                            "medium",
                            source_ip,
                            failed_count,
                            5,
                            "open",
                            timestamp,
                        ),
                    )
                    alert_id = cursor.lastrowid

                additional_alert_created = {
                    "alert_id": alert_id,
                    "rule": "multiple_accounts_from_single_ip",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "distinct_usernames": unique_users,
                    "failed_attempts": failed_count,
                    "window_minutes": 5,
                    "status": "open",
                }   
        connection.commit()

    return {
        "event": {
            "event_id": event_id,
            "event_type": event.event_type,
            "username": event.username,
            "source_ip": source_ip,
            "outcome": event.outcome,
            "timestamp": timestamp,
        },
        "alert_created": alert_created,
        "additional_alert_created": additional_alert_created,
    }

@app.get("/events")
def list_events(
    source_ip: IPvAnyAddress | None = None,
    outcome: Literal["success", "failure"] | None = None,
    limit: int = 10,
    offset: int = 0,
):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 100",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="offset must be zero or greater",
        )

    query = "SELECT * FROM security_events WHERE 1=1"
    count_query = (
        "SELECT COUNT(*) AS total FROM security_events WHERE 1=1"
    )
    params = []

    if source_ip is not None:
        query += " AND source_ip = ?"
        count_query += " AND source_ip = ?"
        params.append(str(source_ip))

    if outcome is not None:
        query += " AND outcome = ?"
        count_query += " AND outcome = ?"
        params.append(outcome)

    query += " ORDER BY event_id LIMIT ? OFFSET ?"

    with closing(get_connection()) as connection:
        total = connection.execute(
            count_query, params
        ).fetchone()["total"]

        rows = connection.execute(
            query, [*params, limit, offset]
        ).fetchall()

    return {
        "count": len(rows),
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [dict(row) for row in rows],
    }

MITRE_MAPPINGS = {
    "repeated_failed_logins": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "multiple_accounts_from_single_ip": {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "tactic": "Credential Access",
    },
}

@app.get("/alerts")
def list_alerts(
    severity: Literal["medium", "high", "critical"] | None = None,
    status: Literal["open", "investigating", "closed"] | None = None,
):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity is not None:
        query += " AND severity = ?"
        params.append(severity)

    if status is not None:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY alert_id"

    with closing(get_connection()) as connection:
        rows = connection.execute(query, params).fetchall()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows],
    }

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found",
            )

        alert = dict(row)

        alert_time = datetime.fromisoformat(alert["created_at"])
        window_start = (
            alert_time - timedelta(minutes=alert["window_minutes"])
        ).isoformat(timespec="microseconds")

        query = """
            SELECT *
            FROM security_events
            WHERE source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
        """
        params = [
            alert["source_ip"],
            window_start,
            alert["created_at"],
        ]

        if alert["rule"] == "repeated_failed_logins":
            query += """
                AND event_type = 'login'
                AND outcome = 'failure'
            """

        query += " ORDER BY timestamp"

        events = connection.execute(query, params).fetchall()

            
        alert["related_events"] = [dict(event) for event in events]

        alert["mitre_attack"] = MITRE_MAPPINGS.get(
            alert["rule"],
            {
                "technique_id": None,
                "technique_name": "Unmapped",
                "tactic": None,
            },
        )

        return alert

@app.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    status: Literal["open", "investigating", "closed"],
):
    with closing(get_connection()) as connection:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE alert_id = ?
            """,
            (status, alert_id),
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Alert not found",
            )

        connection.commit()

        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

    return dict(row)

@app.get("/dashboard/summary")
def dashboard_summary():
    with closing(get_connection()) as connection:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        alert_counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0)
                    AS open_alerts,
                COALESCE(SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END), 0)
                    AS investigating_alerts,
                COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0)
                    AS medium_alerts,
                COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0)
                    AS high_alerts,
                COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
                    AS critical_alerts
            FROM alerts
            """
        ).fetchone()

    return {
        "total_events": event_count,
        "total_alerts": alert_counts["total"],
        "open_alerts": alert_counts["open_alerts"],
        "investigating_alerts": alert_counts["investigating_alerts"],
        "alerts_by_severity": {
            "medium": alert_counts["medium_alerts"],
            "high": alert_counts["high_alerts"],
            "critical": alert_counts["critical_alerts"],
        },
    }

BASE_DIR = Path(__file__).resolve().parent


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.post("/lab/scenarios")
def run_scenario(request: ScenarioRequest):
    now = datetime.now(timezone.utc)

    scenarios = {
        "brute_force": {
            "username": ["demo_user"] * 10,
            "source_ip": "192.0.2.50",
            "outcome": "failure",
        },
        "password_spraying": {
            "username": [f"user_{i}" for i in range(5)],
            "source_ip": "198.51.100.50",
            "outcome": "failure",
        },
        "normal_activity": {
            "username": [f"employee_{i}" for i in range(5)],
            "source_ip": "203.0.113.50",
            "outcome": "success",
        },
    }

    selected = scenarios[request.scenario]
    alerts = {}

    for username in selected["username"]:
        event = SecurityEvent(
            event_type="login",
            username=username,
            source_ip=selected["source_ip"],
            outcome=selected["outcome"],
            timestamp=now,
        )

        result = create_event(event)

        for key in ("alert_created", "additional_alert_created"):
            alert = result.get(key)
            if alert:
                alerts[alert["rule"]] = alert

    return {
        "scenario": request.scenario,
        "events_submitted": len(selected["username"]),
        "alerts": list(alerts.values()),
    }