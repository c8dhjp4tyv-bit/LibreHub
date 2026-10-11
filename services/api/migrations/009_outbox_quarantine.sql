-- Production follow-up: malformed durable outbox events must not block all later work.
-- Keep their original bytes in event_outbox for operator investigation.
-- Each independent consumer must acknowledge/quarantine its own sequence.
CREATE TABLE IF NOT EXISTS outbox_quarantine (
    consumer TEXT NOT NULL CHECK (consumer IN ('automation', 'webhooks')),
    seq INTEGER NOT NULL REFERENCES event_outbox(seq) ON DELETE RESTRICT,
    reason TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    PRIMARY KEY (consumer, seq)
);
CREATE INDEX IF NOT EXISTS outbox_quarantine_timestamp ON outbox_quarantine(quarantined_at);
