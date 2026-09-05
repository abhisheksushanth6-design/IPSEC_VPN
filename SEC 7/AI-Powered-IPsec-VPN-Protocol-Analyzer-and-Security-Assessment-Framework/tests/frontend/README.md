# Frontend tests

The frontend test suite lives inside the frontend package, at
`frontend/tests/`, so that Vitest and Node can resolve `frontend/node_modules`
normally. Run it from the `frontend` directory:

```bash
npm run test        # Vitest + jsdom + Testing Library
npm run typecheck   # TypeScript
npm run build       # production build
```

Backend tests remain in `tests/backend/`.
