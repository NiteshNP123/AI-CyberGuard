---
name: Orval and Zod compatibility
description: Compatibility constraint for generated API validation schemas in this workspace.
---

The current workspace Zod catalog is version 3, while the installed Orval generator can emit Zod 4-only helpers such as `z.int()` for OpenAPI integer schemas. Use generator-compatible schema types or align the dependency before codegen.

**Why:** Codegen itself can succeed while its chained library typecheck fails, blocking every downstream package.

**How to apply:** After changing OpenAPI, always run the package codegen command and its chained library typecheck before building routes or wiring frontend hooks.