import { RotateForm, WebhookForm } from "../../../../../components/dashboard-forms";
import { Time } from "../../../../../components/dashboard";
import { deleteWebhook, replayDelivery, revokeConnection, setConnectionEnabled, setWebhookEnabled } from "../../../actions";
import { devFetch, uuid, type Delivery, type OidcConnection, type Webhook } from "../../../../../lib/developer";

export default async function Integrations({ params }: { params: Promise<{ id: string }> }) {
  const project = uuid((await params).id);
  const [connections, webhooks, deliveries] = await Promise.all([
    devFetch<OidcConnection[]>(`/api/v1/projects/${project}/integrations/oidc`),
    devFetch<Webhook[]>(`/api/v1/projects/${project}/integrations/webhooks`),
    devFetch<Delivery[]>(`/api/v1/projects/${project}/integrations/deliveries?limit=20`),
  ]);
  return (
    <section>
      <h1>Integrations</h1>
      <h2>Trusted GitHub Actions identities</h2>
      <p className="muted">
        Deny by default: a workflow can obtain a short-lived credential only when every listed repository, ref, workflow,
        environment and event rule matches.
      </p>
      {connections.length === 0 ? <p className="muted">No trusted repositories.</p> : null}
      {connections.map((c) => (
        <article key={c.id} className="card-lite">
          <h3>
            {c.name} {c.revoked_at ? "(revoked)" : c.enabled ? "" : "(disabled)"}
          </h3>
          <dl className="facts">
            <div>
              <dt>Repository ID / owner ID</dt>
              <dd>
                {c.policy.repository_id} / {c.policy.repository_owner_id} {c.policy.repository ? `(${c.policy.repository})` : ""}
              </dd>
            </div>
            <div>
              <dt>Fingerprint</dt>
              <dd>
                <code>{c.fingerprint}</code>
              </dd>
            </div>
            <div>
              <dt>Allowed refs</dt>
              <dd>{c.policy.allowed_refs.join(", ")}</dd>
            </div>
            <div>
              <dt>Allowed workflows</dt>
              <dd>{c.policy.allowed_workflows.join(", ")}</dd>
            </div>
            <div>
              <dt>Events</dt>
              <dd>{c.policy.allowed_event_types.join(", ")}</dd>
            </div>
            <div>
              <dt>Permissions</dt>
              <dd>{c.policy.allowed_permissions.join(", ")}</dd>
            </div>
            <div>
              <dt>Credential lifetime</dt>
              <dd>{c.policy.token_ttl_seconds}s</dd>
            </div>
          </dl>
          {c.revoked_at ? null : (
            <div className="row">
              <form action={setConnectionEnabled}>
                <input type="hidden" name="project" value={project} />
                <input type="hidden" name="connection" value={c.id} />
                <input type="hidden" name="enabled" value={String(!c.enabled)} />
                <button>{c.enabled ? "Disable" : "Enable"}</button>
              </form>
              <form action={revokeConnection}>
                <input type="hidden" name="project" value={project} />
                <input type="hidden" name="connection" value={c.id} />
                <button className="danger">Revoke and remove credentials</button>
              </form>
            </div>
          )}
        </article>
      ))}
      <h2>Outbound webhooks</h2>
      {webhooks.length === 0 ? <p className="muted">No webhooks.</p> : null}
      {webhooks.map((w) => (
        <article key={w.id} className="card-lite">
          <h3>{w.url}</h3>
          <dl className="facts">
            <div>
              <dt>Status</dt>
              <dd>{w.enabled ? "Enabled" : `Disabled${w.disabled_reason ? ` (${w.disabled_reason})` : ""}`}</dd>
            </div>
            <div>
              <dt>Secret fingerprint</dt>
              <dd>
                <code>{w.secret_fingerprint}</code>
                {w.secret_rotated_at ? (
                  <>
                    {" "}
                    rotated <Time value={w.secret_rotated_at} />
                  </>
                ) : null}
              </dd>
            </div>
            <div>
              <dt>Events</dt>
              <dd>{w.event_types.join(", ")}</dd>
            </div>
            <div>
              <dt>Last delivery</dt>
              <dd>
                {w.last_delivery ? (
                  <>
                    {w.last_delivery.status}
                    {w.last_delivery.http_status ? ` (HTTP ${w.last_delivery.http_status})` : ""} <Time value={w.last_delivery.at} />
                  </>
                ) : (
                  "none yet"
                )}
              </dd>
            </div>
          </dl>
          <div className="row">
            <RotateForm project={project} webhook={w.id} />
            <form action={setWebhookEnabled}>
              <input type="hidden" name="project" value={project} />
              <input type="hidden" name="webhook" value={w.id} />
              <input type="hidden" name="enabled" value={String(!w.enabled)} />
              <button>{w.enabled ? "Disable" : "Enable"}</button>
            </form>
            <form action={deleteWebhook}>
              <input type="hidden" name="project" value={project} />
              <input type="hidden" name="webhook" value={w.id} />
              <button className="danger">Delete</button>
            </form>
          </div>
        </article>
      ))}
      <h3>Add a webhook</h3>
      <WebhookForm project={project} />
      <h2>Recent deliveries</h2>
      {deliveries.length === 0 ? (
        <p className="muted">No deliveries.</p>
      ) : (
        <table className="data-table">
          <caption className="visually-hidden">Recent webhook deliveries</caption>
          <thead>
            <tr>
              <th scope="col">Event</th>
              <th scope="col">Status</th>
              <th scope="col">Attempts</th>
              <th scope="col">HTTP</th>
              <th scope="col">Created</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((d) => (
              <tr key={d.id}>
                <td>{d.event_type}</td>
                <td>{d.status.replace(/_/g, " ")}</td>
                <td>{d.attempts}</td>
                <td>{d.last_http_status ?? d.last_error ?? "—"}</td>
                <td>
                  <Time value={d.created_at} />
                </td>
                <td>
                  {["delivered", "failed", "dead_letter"].includes(d.status) ? (
                    <form action={replayDelivery}>
                      <input type="hidden" name="project" value={project} />
                      <input type="hidden" name="delivery" value={d.id} />
                      <button>Replay</button>
                    </form>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
