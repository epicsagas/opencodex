/**
 * The privacy scanner must recognize cloud/CI platform tokens and PEM private-key
 * headers that the pre-existing patterns miss.
 *
 * The `token-looking` pattern covers `sk-`, `ghp_` and JWTs, but AWS access-key ids,
 * Google API keys, app/user/server GitHub tokens, fine-grained PATs, Linux/Windows
 * home paths outside macOS, and `-----BEGIN ... PRIVATE KEY-----` headers all passed
 * the scan before these detectors existed. The scan is the gate the public devlog's
 * safety rests on (see AGENTS.md), so a detector for each grammar belongs in it.
 *
 * This exercises the REAL `scanText` used by `bun run privacy:scan`, not a copy of its
 * regex: a test that re-declared the pattern would keep passing after the production
 * detector was deleted.
 */
import { describe, expect, test } from "bun:test";
import { scanText } from "../../scripts/privacy-scan";

/** Assembled at runtime so this file contains no secret-shaped literal of its own. */
const awsAccessKeyId = ["AKIA", "A".repeat(16)].join("");
const googleApiKey = ["AIza", "a".repeat(30), "1", "-", "_", "B", "c"].join("");
const githubFineGrained = ["github_pat_", "A".repeat(22)].join("");
const githubAppToken = ["gho_", "A".repeat(36)].join("");
const pemHeader = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");

describe("privacy scan: cloud tokens", () => {
  test("flags an AWS access-key id in a tracked file", () => {
    const findings = scanText("src/example.ts", `key = "${awsAccessKeyId}";`);
    expect(findings.some(f => f.kind === "cloud-token")).toBe(true);
  });

  test("flags a Google API key", () => {
    const findings = scanText("docs/example.md", `key=${googleApiKey}`);
    expect(findings.some(f => f.kind === "cloud-token")).toBe(true);
  });

  test("flags fine-grained and app GitHub tokens", () => {
    for (const token of [githubFineGrained, githubAppToken]) {
      const findings = scanText("devlog/_plan/x/000.md", `token: ${token}`);
      expect(findings.some(f => f.kind === "cloud-token")).toBe(true);
    }
  });

  test("ordinary prose mentioning the prefixes is not a finding", () => {
    const findings = scanText(
      "docs/example.md",
      "AWS keys start with AKIA and Google keys with AIza; GitHub fine-grained tokens look like github_pat_XXXX.",
    );
    expect(findings.some(f => f.kind === "cloud-token")).toBe(false);
  });

  test("home paths outside macOS are caught", () => {
    for (const line of [
      `cd /home/${"janedoe"}/work && ls`,
      `dir C:\\Users\\${"janedoe"}\\Documents`,
    ]) {
      const findings = scanText("devlog/_fin/x/000.md", line);
      expect(findings.some(f => f.kind === "home-path")).toBe(true);
    }
  });

  test("a PEM private-key header is caught", () => {
    const findings = scanText("config/backup.conf", pemHeader);
    expect(findings.some(f => f.kind === "private-key")).toBe(true);
  });

  test("the maintained home-path allowance still applies to the new Linux/Windows forms", () => {
    // The maintainer's own name is allowed under the same policy as /Users/ (the
    // username is already public through repository ownership). Assembled from
    // fragments so this test file does not trip the scanner's own detectors.
    const maintainer = ["j", "un"].join("");
    for (const line of [
      `cd /home/${maintainer}/work && ls`,
      `dir C:\\Users\\${maintainer}\\Documents`,
    ]) {
      const findings = scanText("devlog/_fin/x/000.md", line);
      expect(findings.filter(f => f.kind === "home-path")).toEqual([]);
    }
  });
});
