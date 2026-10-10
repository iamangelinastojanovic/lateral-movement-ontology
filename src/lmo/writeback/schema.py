"""Append-only analyst judgements. Not ground truth."""

DECISION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS decisions (
    decision_id VARCHAR PRIMARY KEY,
    alert_uid VARCHAR NOT NULL,
    event_uid VARCHAR,
    action VARCHAR NOT NULL,
    note VARCHAR,
    analyst VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL,
    supersedes VARCHAR
)
"""

ACTIONS = ("true_positive", "false_positive", "inconclusive")


def ensure_decision_tables(con) -> None:
    con.execute(DECISION_TABLE_SQL)
