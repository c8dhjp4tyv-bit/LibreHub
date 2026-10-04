export default function Loading() {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="eyebrow">LIBREHUB</span>
      <h1>Loading the catalog…</h1>
      <div className="skeleton" />
      <span className="sr-only">Please wait</span>
    </div>
  );
}
