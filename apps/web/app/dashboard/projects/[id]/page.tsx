import { redirect } from "next/navigation";
import { uuid } from "../../../../lib/developer";

export default async function ProjectHome({ params }: { params: Promise<{ id: string }> }) {
  redirect(`/dashboard/projects/${uuid((await params).id)}/automations`);
}
