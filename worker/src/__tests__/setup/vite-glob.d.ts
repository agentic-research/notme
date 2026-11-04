// `import.meta.glob` is Vite syntax, rewritten at transform time by the test
// runner, so it never exists at runtime as a method. `vite/client` declares it
// but is not resolvable from this package (vite is vitest's transitive dep),
// so declare only the one overload warm-worker-modules.ts uses. Type-check only.
interface ImportMeta {
  glob(
    patterns: string[],
    options: { eager: true },
  ): Record<string, unknown>;
}
