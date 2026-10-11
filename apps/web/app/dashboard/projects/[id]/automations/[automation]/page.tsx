import { runAutomation } from "../../../../actions";
import { RunTable, Time } from "../../../../../../components/dashboard";
import { devFetch, uuid, type Automation, type Run } from "../../../../../../lib/developer";

export default async function AutomationDetail({ params }: { params: Promise<{ id: string; automation: string }> }) {
  const { id, automation: automationId } = await params;
  const project = uuid(id);
  const automation = uuid(automationId);
  const [definition, runs] = await Promise.all([
    devFetch<Automation>(`/api/v1/projects/${project}/automations/${automation}`),
    devFetch<Run[]>(`/api/v1/projects/${project}/automations/${automation}/runs?limit=25`),
  ]);
  const policy = Object.entries(definition.spec.policy ?? {}).filter(([, v]) => typeof v === "boolean");
  return (
    <section>
      <h1>{definition.name}</h1>
      <p className="muted">
        Version {definition.current_version} (publication rights require version ≥ {definition.min_valid_version}) ·{" "}
        {definition.enabled ? "enabled" : "disabled"} · updated <Time value={definition.updated_at} />
      </p>
      <h2>Triggers</h2>
      <ul>
        {definition.spec.triggers.map((trigger, i) => (
          <li key={i}>
            <code>{trigger.type}</code>
            {Object.entries(trigger)
              .filter(([k]) => k !== "type")
              .map(([k, v]) => (
                <span key={k}>
                  {" "}
                  {k}: <code>{JSON.stringify(v)}</code>
                </span>
              ))}
          </li>
        ))}
      </ul>
      {definition.schedules && definition.schedules.length > 0 ? (
        <p>
          Next scheduled run (UTC):{" "}
          {definition.schedules.map((s) => (
            <Time key={s.trigger_index} value={s.next_run_at} />
          ))}
          {definition.schedules_enabled ? "" : " (schedules are switched off)"}
        </p>
      ) : null}
      <h2>Steps</h2>
      <ol>
        {definition.spec.steps.map((step) => (
          <li key={step.id}>
            <strong>{step.id}</strong> — <code>{step.uses}</code>
            {step.needs && step.needs.length > 0 ? <> after {step.needs.join(", ")}</> : null}
            {step.with && Object.keys(step.with).length > 0 ? <> · <code>{JSON.stringify(step.with)}</code></> : null}
          </li>
        ))}
      </ol>
      <h2>Release policy</h2>
      <ul>
        {policy.map(([key, value]) => (
          <li key={key}>
            {key.replace(/_/g, " ")}: <strong>{value ? "yes" : "no"}</strong>
          </li>
        ))}
      </ul>
      {definition.enabled ? (
        <form action={runAutomation}>
          <input type="hidden" name="project" value={project} />
          <input type="hidden" name="automation" value={automation} />
          <button>Run now</button>
        </form>
      ) : null}
      <h2>Recent runs</h2>
      <RunTable runs={runs} project={project} />
    </section>
  );
}
