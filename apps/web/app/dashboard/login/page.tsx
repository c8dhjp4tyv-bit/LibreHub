import { LoginForm } from "../../../components/dashboard-forms";

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ expired?: string }> }) {
  const { expired } = await searchParams;
  return (
    <section>
      <h1>Developer sign in</h1>
      <LoginForm expired={expired === "1"} />
    </section>
  );
}
