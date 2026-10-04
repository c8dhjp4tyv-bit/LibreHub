"use client";

import { useState } from "react";
import { publicApiBase, type ReportReason } from "../lib/catalog";

export function ReportForm({ appId }: { appId: string }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<ReportReason>("policy_violation");
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const res = await fetch(`${publicApiBase}/api/v1/catalog/apps/${encodeURIComponent(appId)}/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reason,
          message: message.trim() ? message.trim() : undefined,
        }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.message || "Failed to submit report");
      }

      setSubmitted(true);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Error submitting report";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="report-container">
      {!open && (
        <button
          type="button"
          className="report-toggle-btn"
          onClick={() => setOpen(true)}
        >
          Report this application ⚑
        </button>
      )}

      {open && (
        <div className="report-dialog">
          <h3>Report application: {appId}</h3>
          <p className="muted">
            Reports are signals evaluated by platform operators in accordance with LibreHub moderation policies.
            Reports do not automatically hide or remove applications.
          </p>

          {submitted ? (
            <div className="report-success">
              <p><strong>Thank you for your report.</strong></p>
              <p className="muted">
                Our moderation team will review the report and take action if platform policies are violated.
              </p>
              <button
                type="button"
                className="report-close-btn"
                onClick={() => {
                  setOpen(false);
                  setSubmitted(false);
                  setMessage("");
                }}
              >
                Close
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="report-form">
              {error && <p className="report-error">{error}</p>}

              <label>
                Reason for report:
                <select
                  value={reason}
                  onChange={(e) => setReason(e.target.value as ReportReason)}
                  disabled={submitting}
                >
                  <option value="policy_violation">Platform policy violation</option>
                  <option value="malware">Suspected malware or security issue</option>
                  <option value="privacy_violation">Privacy violation or undisclosed telemetry</option>
                  <option value="copyright_infringement">Copyright or trademark infringement</option>
                  <option value="broken_build">Severely broken or non-functioning release</option>
                  <option value="security_vulnerability">Security vulnerability</option>
                  <option value="impersonation">Impersonation</option>
                  <option value="other">Other concern</option>
                </select>
              </label>

              <label>
                Details / Evidence (optional):
                <textarea
                  rows={4}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Provide context or links to relevant issue trackers, reproduction steps, or license proofs…"
                  disabled={submitting}
                  maxLength={2000}
                />
              </label>

              <div className="report-actions">
                <button type="submit" disabled={submitting}>
                  {submitting ? "Submitting…" : "Submit report"}
                </button>
                <button
                  type="button"
                  className="report-cancel-btn"
                  onClick={() => setOpen(false)}
                  disabled={submitting}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
}
