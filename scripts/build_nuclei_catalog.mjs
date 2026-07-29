#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [cvePath, treePath, outputPath, revision] = process.argv.slice(2);
if (!cvePath || !treePath || !outputPath || !revision) {
  throw new Error(
    "usage: build_nuclei_catalog.mjs <cves.jsonl> <tree.json> <output.json> <revision>",
  );
}

const repository = "https://github.com/projectdiscovery/nuclei-templates";
const cveRows = readFileSync(cvePath, "utf8")
  .trim()
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const tree = JSON.parse(readFileSync(treePath, "utf8"));
const records = new Map();
const treePaths = new Set(
  (tree.tree ?? [])
    .filter(
      (entry) =>
        entry.type === "blob" &&
        typeof entry.path === "string" &&
        entry.path.endsWith(".yaml"),
    )
    .map((entry) => entry.path),
);

for (const row of cveRows) {
  if (
    typeof row.ID !== "string" ||
    !/^CVE-\d{4}-\d{4,7}$/i.test(row.ID) ||
    typeof row.file_path !== "string" ||
    !treePaths.has(row.file_path)
  ) {
    continue;
  }
  const cve = row.ID.toUpperCase();
  records.set(row.file_path, {
    id: cve,
    path: row.file_path,
    cves: [cve],
    technologies: [],
    provenance: `${repository}/blob/${revision}/${row.file_path}`,
  });
}

for (const entry of tree.tree ?? []) {
  if (
    entry.type !== "blob" ||
    typeof entry.path !== "string" ||
    !entry.path.startsWith("http/technologies/") ||
    !entry.path.endsWith(".yaml")
  ) {
    continue;
  }
  const stem = entry.path
    .split("/")
    .at(-1)
    .replace(/\.yaml$/, "");
  const technologies = [...new Set(
    stem
      .toLowerCase()
      .split(/[^a-z0-9.]+/)
      .filter((token) => token.length >= 3 && !/^\d+$/.test(token)),
  )].sort();
  records.set(entry.path, {
    id: stem,
    path: entry.path,
    cves: [],
    technologies,
    provenance: `${repository}/blob/${revision}/${entry.path}`,
  });
}

const payload = {
  schema_version: 1,
  repository,
  revision,
  source_sha256: {
    cves_jsonl: createHash("sha256").update(readFileSync(cvePath)).digest("hex"),
    github_tree: createHash("sha256").update(readFileSync(treePath)).digest("hex"),
  },
  templates: [...records.values()].sort((a, b) => a.path.localeCompare(b.path)),
};
writeFileSync(outputPath, `${JSON.stringify(payload)}\n`);
