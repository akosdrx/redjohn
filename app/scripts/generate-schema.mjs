/**
 * Generates renderer/src/lib/schema.d.ts from the canonical API contract
 * at ../../rj-cli/contracts/openapi.yaml.
 *
 * The generated file is committed and MUST NOT be hand-edited.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";
import openapiTS, { astToString } from "openapi-typescript";

const here = dirname(fileURLToPath(import.meta.url));
for (const [contract, output] of [
  ["openapi.yaml", "schema.d.ts"],
  ["local-integrations.openapi.yaml", "integrations-schema.d.ts"],
]) {
  const contractPath = resolve(here, "../../contracts", contract);
  const doc = yamlLoad(readFileSync(contractPath, "utf8"));
  const header = `/**
 * GENERATED FILE — DO NOT HAND-EDIT.
 * Generated from contracts/${contract} by \`pnpm schema:generate\`
 * (app/scripts/generate-schema.mjs). Regenerate after any contract change.
 */
`;

  writeFileSync(resolve(here, "../renderer/src/lib", output), header + astToString(await openapiTS(doc)));
  console.log(`${output} written from ${contractPath}`);
}
