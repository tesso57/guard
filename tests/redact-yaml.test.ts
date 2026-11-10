import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { parseDocument, stringify } from "yaml";
import { redactString } from "../extensions/guard/redact.ts";

test("YAML flow redaction keeps unrelated values parseable", () => {
  const notes = ["simple", "user's", 'abc:"open', "a,b", "{text}", "value:colon", "#hash", "a\nb", '"quotes"', " leading"];
  const values: unknown[] = ["opaque-flow-oracle", ["opaque-flow-oracle", "more"], { nested: "opaque-flow-oracle" }, { array: [{ deep: "opaque-flow-oracle" }] }];
  for (const note of notes) for (const value of values) for (const reverse of [false, true]) {
    const entry = reverse ? { value, note, name: "API_TOKEN" } : { name: "API_TOKEN", note, value };
    const source = stringify({ env: [entry, { name: "LOG_LEVEL", value: "visible" }] }, { collectionStyle: "flow", lineWidth: 0 });
    const output = redactString(source);
    assert.ok(!output.includes("opaque-flow-oracle"), `secret remains for note ${JSON.stringify(note)}`);
    const document = parseDocument(output);
    assert.deepEqual(document.errors, [], `redacted YAML is invalid for note ${JSON.stringify(note)}`);
    const parsed = document.toJS() as { env: { name: string; note?: string; value: unknown }[] };
    assert.equal(parsed.env[0].value, "[REDACTED]");
    assert.equal(parsed.env[0].note, note);
    assert.equal(parsed.env[1].value, "visible");
  }
});

test("mixed YAML block and flow styles preserve unrelated fields", () => {
  const cases: { source: string; visible: (value: any) => unknown }[] = [
    {
      source: "config:\n  password: opaque-a\n  env: [{name: API_TOKEN, value: opaque-b}, {name: LOG_LEVEL, value: visible}]\n",
      visible: (value) => value.config.env[1],
    },
    {
      source: "env:\n  - {value: opaque-a,\n     note: a\n\n       b,\n     name: API_TOKEN}\nnotes: |\n  visible\n",
      visible: (value) => [value.env[0].note, value.notes],
    },
    {
      source: "credentials:\n  nested: opaque-a\nflow: {name: API_TOKEN, value: {nested: opaque-b}, other: visible}\n",
      visible: (value) => value.flow.other,
    },
  ];
  for (const { source, visible } of cases) {
    const before = parseDocument(source);
    assert.deepEqual(before.errors, []);
    const output = redactString(source);
    assert.doesNotMatch(output, /opaque-[ab]/);
    const after = parseDocument(output);
    assert.deepEqual(after.errors, []);
    assert.deepEqual(visible(after.toJS()), visible(before.toJS()));
  }
});

test("complex flow mappings fail closed without exposing secrets", () => {
  const deeplyNested = "{outer: ".repeat(33)
    + "{name: API_TOKEN, value: opaque-deep-secret}"
    + "}".repeat(33);
  const wideMapping = "{name: API_TOKEN, value: opaque-before-secret, "
    + Array.from({ length: 50_010 }, (_, index) => `field${index}: x`).join(", ")
    + ", extra: opaque-after-secret}";

  for (const source of [deeplyNested, wideMapping]) {
    assert.doesNotMatch(redactString(source), /opaque-(?:deep|before|after)-secret/);
  }
});

test("YAML descriptors with tagged or explicit keys still protect their values", () => {
  const cases = [
    "env: [{!!str name: API_TOKEN, value: opaque-secret, note: visible}]",
    "env: [{? name: API_TOKEN, value: opaque-secret, note: visible}]",
    "env:\n  - !!str name: API_TOKEN\n    value: opaque-secret\n    note: visible\n",
    "env:\n  - !<tag:yaml.org,2002:str> name: API_TOKEN\n    value: opaque-secret\n    note: visible\n",
    "env: [{!<tag:yaml.org,2002:str> name: API_TOKEN, value: opaque-secret, note: visible}]",
    "env: [{!<tag:yaml.org,2002:str>\n  name: API_TOKEN, value: opaque-secret, note: visible}]",
    "env: [{name: API_TOKEN, !<tag:yaml.org,2002:str>\n  value: opaque-secret, note: visible}]",
    "env: [{!<tag:yaml.org,2002:str> # key tag\n  name: API_TOKEN, value: opaque-secret, note: visible}]",
    "env: [{name: API_TOKEN, !<tag:yaml.org,2002:str> # key tag\n  value: opaque-secret, note: visible}]",
    "env: [{name\n  : API_TOKEN, value: opaque-secret, note: visible}]",
    "env: [{name # key comment\n  : API_TOKEN, value: opaque-secret, note: visible}]",
  ];
  for (const source of cases) {
    assert.deepEqual(parseDocument(source).errors, []);
    const output = redactString(source);
    assert.doesNotMatch(output, /opaque-secret/);
    const document = parseDocument(output);
    assert.deepEqual(document.errors, []);
    assert.equal((document.toJS() as { env: { note: string }[] }).env[0].note, "visible");
  }
});

test("tagged and anchored YAML value keys do not expose named secrets", () => {
  for (const key of ["!!str value", "&key value", "!<tag:yaml.org,2002:str> value"]) {
    for (const value of ["opaque-secret", "|\n      opaque-secret"]) {
      const source = `env:\n  - name: API_TOKEN\n    ${key}: ${value}\n    note: visible\n`;
      assert.deepEqual(parseDocument(source).errors, []);
      const output = redactString(source);
      assert.doesNotMatch(output, /opaque-secret/);
      const document = parseDocument(output);
      assert.deepEqual(document.errors, []);
      assert.equal((document.toJS() as { env: { note: string }[] }).env[0].note, "visible");
    }
  }
});

test("multiline explicit YAML keys cannot expose named secret values", () => {
  const cases = [
    "env:\n  - ? name\n    : API_TOKEN\n    value: opaque-secret\n",
    "env:\n  - name: API_TOKEN\n    ? value\n    : opaque-secret\n",
  ];
  for (const source of cases) {
    assert.deepEqual(parseDocument(source).errors, []);
    assert.doesNotMatch(redactString(source), /opaque-secret/);
  }
});

test("redacting an alias also protects its anchor definition", () => {
  for (const source of [
    "common: &shared opaque-anchor-secret\nenv:\n  - name: API_TOKEN\n    value: *shared\n",
    "{common: &shared opaque-anchor-secret, env: [{name: API_TOKEN, value: *shared}]}",
    "common: &shared opaque-anchor-secret\nenv:\n  - name: LOG_LEVEL\n    value: *shared\n  - name: API_TOKEN\n    value: *shared\n",
  ]) {
    assert.deepEqual(parseDocument(source).errors, []);
    assert.doesNotMatch(redactString(source), /opaque-anchor-secret/);
  }
});

test("unrelated YAML aliases remain available to the judge", () => {
  const source = "common: &shared visible\nenv:\n  - name: LOG_LEVEL\n    value: *shared\n";
  assert.deepEqual(parseDocument(source).errors, []);
  assert.equal(redactString(source), source);
});

test("YAML merge aliases cannot expose inherited named secrets", () => {
  const cases = [
    "common: &defaults\n  value: opaque-merge-secret\nenv:\n  - name: API_TOKEN\n    <<: *defaults\n",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, <<: *defaults}]}",
    "common: &defaults {value: opaque-merge-secret}\nenv:\n  - name: API_TOKEN\n    !!merge <<: *defaults\n",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, !!merge <<: *defaults}]}",
    "common: &defaults {value: opaque-merge-secret}\nenv:\n  - name: API_TOKEN\n    !<tag:yaml.org,2002:merge> <<: *defaults\n",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, !<tag:yaml.org,2002:merge> <<: *defaults}]}",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, !!merge # tag comment\n  <<: *defaults}]}",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, !<tag:yaml.org,2002:merge>\n  <<: *defaults}]}",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, <<\n  : *defaults}]}",
    "{common: &defaults {value: opaque-merge-secret}, env: [{name: API_TOKEN, << # merge key\n  : *defaults}]}",
  ];
  for (const source of cases) {
    const document = parseDocument(source, { merge: true, version: "1.1" });
    assert.deepEqual(document.errors, []);
    assert.equal((document.toJS() as { env: { value: string }[] }).env[0].value, "opaque-merge-secret");
    assert.doesNotMatch(redactString(source), /opaque-merge-secret/);
  }
});

test("long and incomplete YAML tags do not stall redaction", () => {
  const moduleUrl = new URL("../extensions/guard/redact.ts", import.meta.url).href;
  const code = `import { redactString } from ${JSON.stringify(moduleUrl)};
    const input = '{!<tag:yaml.org,2002:str> #' + ' '.repeat(500_000) + '\\n name: API_TOKEN, value: opaque-long-secret}';
    if (redactString(input).includes('opaque-long-secret')) process.exit(1);
    for (const partial of [
      '{!x ' + ' '.repeat(200_000) + '!}',
      '{!x #' + ' '.repeat(200_000) + '\\n !}',
      '{!<' + 'x'.repeat(500_000),
      '{' + 'a '.repeat(200_000) + '!}',
    ]) redactString(partial);`;
  execFileSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], { timeout: 5_000, stdio: "pipe" });
});
