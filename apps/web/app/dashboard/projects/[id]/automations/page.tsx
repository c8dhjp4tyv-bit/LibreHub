import Link from "next/link";
import { runAutomation } from "../../../actions";
import { AutomationCard } from "../../../../../components/dashboard";
import { devFetch, uuid, type Automation } from "../../../../../lib/developer";

export default async function Automations({ params }: { params: Promise<{ id: string }> }) {
  const project = uuid((await params).id);
  const automations = await devFetch<Automation[]>(`/api/v1/projects/${project}/automations?limit=100`);
  return (
    <section>
      <h1>Automations</h1>
      <p>
        <Link href={`/dashboard/projects/${project}/runs`}>Run history</Link> ·{" "}
        <Link href={`/dashboard/projects/${project}/integrations`}>Integrations</Link>
      </p>
      {automations.length === 0 ? <p className="muted">No automations. Create one with `librehub automation create`.</p> : null}
      {automations.map((automation) => (
        <div key={automation.id}>
          <AutomationCard automation={automation} project={project} />
          {automation.enabled ? (
            <form action={runAutomation}>
              <input type="hidden" name="project" value={project} />
              <input type="hidden" name="automation" value={automation.id} />
              <button>Run now</button>
            </form>
          ) : null}
        </div>
      ))}
    </section>
  );
}
