import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="max-w-reading space-y-4">
      <h1 className="text-2xl font-medium">This page does not exist</h1>
      <p className="text-muted">
        The address you followed is not part of the application.
      </p>
      <Link to="/" className="text-signal underline-offset-4 hover:underline">
        Go to the start page
      </Link>
    </div>
  );
}
