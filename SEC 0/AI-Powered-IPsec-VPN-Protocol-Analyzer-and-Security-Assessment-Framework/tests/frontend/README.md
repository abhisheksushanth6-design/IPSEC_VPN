# Frontend tests

No frontend test runner is configured in Section 0. The frontend is currently
verified by the TypeScript check and the production build, both of which run in
CI:

```bash
cd frontend
npm run typecheck
npm run build
```

A component test runner (Vitest + Testing Library) will be added when the
dashboard views from Section 1 onwards exist and there is real behaviour to
assert against.
