import Link from "next/link";
import { devFetch, type Project } from "../../../lib/developer";

export default async function Projects() {
  const projects = await devFetch<Project[]>("/api/v1/projects?limit=100");
  return (
    <section>
      <h1>Projects</h1>
      {projects.length === 0 ? <p className="muted">No projects yet. Create one with the API or `librehub project create`.</p> : null}
      <ul className="plain">
        {projects.map((project) => (
          <li key={project.id} className="card-lite">
            <h3>{project.display_name}</h3>
            <p className="muted">
              {project.slug} · {project.status} · {project.repository.url}
            </p>
            <p className="row">
              <Link href={`/dashboard/projects/${project.id}/automations`}>Automations</Link>
              <Link href={`/dashboard/projects/${project.id}/runs`}>Runs</Link>
              <Link href={`/dashboard/projects/${project.id}/integrations`}>Integrations</Link>
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
