// wrangler-template-migrations.test.ts — a fresh Cloudflare account can deploy
// the templates (notme-b556a4).
//
// Cloudflare no longer creates KV-backed Durable Object namespaces on an
// account that does not already hold one: "Creating new namespaces with the
// key-value storage backend is no longer supported for accounts without an
// existing key-value-backed namespace" (developers.cloudflare.com, Durable
// Object class migrations). A migration's `new_classes` selects that backend,
// so a self-hoster who copied a template that declared one had their first
// `wrangler deploy` refused.
//
// The templates therefore create every class with `new_sqlite_classes`. The
// tag NAMES stay v1, v2, in order: wrangler matches a deployed Worker's
// recorded tag against this list to decide which entries are still to apply
// ("Migration tags are treated like unique names and are used to determine
// which migrations have already been applied"), so an existing deployment
// that copies a fresh template still finds its tag and applies nothing.
// Renaming or reordering them is what would break a live deploy.
//
// Asserted against the committed templates only. The live worker/wrangler.toml
// is gitignored, and its applied history is not this file's to change.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (name: string) =>
  readFileSync(fileURLToPath(new URL(`../../${name}`, import.meta.url).href), "utf8");

/** Every [[migrations]] / [[env.X.migrations]] block, keyed by its own lines. */
function migrationBlocks(toml: string): Array<{ header: string; body: Record<string, string> }> {
  const blocks: Array<{ header: string; body: Record<string, string> }> = [];
  let current: { header: string; body: Record<string, string> } | null = null;
  for (const raw of toml.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    const header = line.match(/^\[{1,2}\s*([^\]]+?)\s*\]{1,2}$/);
    if (header) {
      current = /(^|\.)migrations$/.test(header[1]!) ? { header: header[1]!, body: {} } : null;
      if (current) blocks.push(current);
      continue;
    }
    const kv = line.match(/^([A-Za-z_]+)\s*=\s*(.+)$/);
    if (current && kv) current.body[kv[1]!] = kv[2]!;
  }
  return blocks;
}

const classesIn = (value: string | undefined) =>
  value ? [...value.matchAll(/"([^"]+)"/g)].map((m) => m[1]!) : [];

for (const template of ["wrangler.toml.example", "wrangler.e2e.toml"]) {
  describe(`${template} migrations`, () => {
    const blocks = migrationBlocks(read(template));

    it("declares migrations at all", () => {
      expect(blocks.length).toBeGreaterThan(0);
    });

    it("creates no KV-backed class (new_classes), which a fresh account refuses", () => {
      const kvBacked = blocks.filter((b) => "new_classes" in b.body);
      expect(kvBacked.map((b) => `${b.header} ${b.body.tag}: ${b.body.new_classes}`)).toEqual([]);
    });

    it("creates both Durable Object classes as SQLite-backed", () => {
      const sqlite = blocks.flatMap((b) => classesIn(b.body.new_sqlite_classes));
      expect(sqlite).toContain("RevocationAuthority");
      expect(sqlite).toContain("SigningAuthority");
    });

    it("keeps the tag names an existing deployment has recorded, in order", () => {
      const topLevel = blocks.filter((b) => b.header === "migrations");
      expect(topLevel.map((b) => b.body.tag)).toEqual(['"v1"', '"v2"']);
    });
  });
}
