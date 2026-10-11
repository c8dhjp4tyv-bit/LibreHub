"use client";
import { useActionState } from "react";
import {
  createWebhook,
  decideApproval,
  login,
  rotateWebhook,
  type FormState,
} from "../app/dashboard/actions";

const initial: FormState = {};

function Feedback({ state }: { state: FormState }) {
  return (
    <>
      {state.error ? (
        <p className="alert" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.ok ? <p role="status">{state.ok}</p> : null}
      {state.secret ? (
        <p className="secret-once">
          <label>
            Signing secret (shown once)
            <input readOnly value={state.secret} onFocus={(e) => e.currentTarget.select()} aria-label="Signing secret" />
          </label>
        </p>
      ) : null}
    </>
  );
}

export function LoginForm({ expired }: { expired: boolean }) {
  const [state, action, pending] = useActionState(login, initial);
  return (
    <form action={action} className="stack">
      {expired ? <p role="status">Your session ended. Sign in again.</p> : null}
      <label>
        LibreHub API token
        <input name="token" type="password" autoComplete="off" spellCheck={false} required />
      </label>
      <p className="muted">
        Create a token with <code>librehub-admin create-token</code>. It is kept in an httpOnly cookie and is never
        visible to page scripts.
      </p>
      <button disabled={pending}>Sign in</button>
      <Feedback state={state} />
    </form>
  );
}

export function ApprovalForm({ approval }: { approval: string }) {
  const [state, action, pending] = useActionState(decideApproval, initial);
  return (
    <form action={action} className="stack">
      <input type="hidden" name="approval" value={approval} />
      <label>
        Reason (optional, recorded in the audit trail)
        <input name="reason" maxLength={500} />
      </label>
      <div className="row">
        <button name="decision" value="approve" disabled={pending}>
          Approve release
        </button>
        <button name="decision" value="reject" className="danger" disabled={pending}>
          Reject
        </button>
      </div>
      <Feedback state={state} />
    </form>
  );
}

export const WEBHOOK_EVENTS = [
  "build.started",
  "build.succeeded",
  "build.failed",
  "publication.started",
  "publication.succeeded",
  "publication.failed",
  "security.analysis_ready",
  "security.analysis_failed",
  "attestation.ready",
  "attestation.failed",
  "automation.started",
  "automation.completed",
  "automation.failed",
  "automation.approval_required",
];

export function WebhookForm({ project }: { project: string }) {
  const [state, action, pending] = useActionState(createWebhook, initial);
  return (
    <form action={action} className="stack">
      <input type="hidden" name="project" value={project} />
      <label>
        Receiver URL (https, public)
        <input name="url" type="url" required placeholder="https://hooks.example.com/librehub" />
      </label>
      <label>
        Description
        <input name="description" maxLength={200} />
      </label>
      <fieldset>
        <legend>Events</legend>
        {WEBHOOK_EVENTS.map((event) => (
          <label key={event} className="check">
            <input type="checkbox" name="events" value={event} defaultChecked={event.startsWith("publication.")} /> {event}
          </label>
        ))}
      </fieldset>
      <button disabled={pending}>Add webhook</button>
      <Feedback state={state} />
    </form>
  );
}

export function RotateForm({ project, webhook }: { project: string; webhook: string }) {
  const [state, action, pending] = useActionState(rotateWebhook, initial);
  return (
    <form action={action} className="stack">
      <input type="hidden" name="project" value={project} />
      <input type="hidden" name="webhook" value={webhook} />
      <button disabled={pending}>Rotate secret</button>
      <Feedback state={state} />
    </form>
  );
}
