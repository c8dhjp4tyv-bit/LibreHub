"use client";
export default function ErrorPage({ reset }: { reset: () => void }) {
  return (
    <div className="empty" role="alert">
      <h1>The catalog is taking a break</h1>
      <p>
        We couldn’t load this page. Please check your filters or try again in a
        moment.
      </p>
      <button onClick={reset}>Try again</button>
    </div>
  );
}
