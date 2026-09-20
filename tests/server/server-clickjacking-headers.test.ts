import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { browserSecurityHeaders, corsHeaders } from "../../src/server/auth-cors";
import { serveGuiFile } from "../../src/server/gui-static";
import { removeTreeWithRetry } from "../helpers/remove-tree";

const EXPECTED = {
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "frame-ancestors 'none'; script-src 'self'",
};

describe("clickjacking response headers", () => {
  test("the shared browser header set denies all framing", () => {
    expect(browserSecurityHeaders()).toEqual(EXPECTED);
  });

  test("API and preflight headers include the framing policy", () => {
    expect(corsHeaders()).toMatchObject(EXPECTED);
  });

  test("static dashboard responses include the framing policy", () => {
    const guiDist = mkdtempSync(join(tmpdir(), "ocx-gui-headers-"));
    writeFileSync(join(guiDist, "index.html"), "<!doctype html><title>test</title>");
    try {
      const response = serveGuiFile("/", guiDist);
      expect(response).not.toBeNull();
      expect(response?.headers.get("X-Frame-Options")).toBe("DENY");
      expect(response?.headers.get("Content-Security-Policy")).toBe("frame-ancestors 'none'; script-src 'self'");
    } finally {
      removeTreeWithRetry(guiDist);
    }
  });
});

describe("dashboard script-src policy", () => {
  const servedCsp = (html: string): string => {
    const guiDist = mkdtempSync(join(tmpdir(), "ocx-gui-csp-"));
    writeFileSync(join(guiDist, "index.html"), html);
    try {
      const response = serveGuiFile("/", guiDist);
      expect(response).not.toBeNull();
      return response?.headers.get("Content-Security-Policy") ?? "";
    } finally {
      removeTreeWithRetry(guiDist);
    }
  };

  test("an inline bootstrap script gets a matching sha256 source; src-tagged scripts do not", () => {
    const inlineBody = '\n  var t = localStorage.getItem("ocx-theme");\n';
    const csp = servedCsp(
      `<!doctype html><script>${inlineBody}</script><script src="/assets/index-x.js"></script>`,
    );
    const expectedHash = `'sha256-${createHash("sha256").update(inlineBody).digest("base64")}'`;
    expect(csp).toContain("'self'");
    expect(csp).toContain(expectedHash);
    expect(csp.match(/'sha256-/g)).toHaveLength(1);
  });

  test("a changed inline script invalidates the old hash instead of being allowed", () => {
    const oldBody = "var a = 1;";
    const newBody = "var a = 2;";
    const oldHash = `'sha256-${createHash("sha256").update(oldBody).digest("base64")}'`;
    const csp = servedCsp(`<!doctype html><script>${newBody}</script>`);
    expect(csp).not.toContain(oldHash);
    expect(csp).toContain(`'sha256-${createHash("sha256").update(newBody).digest("base64")}'`);
  });
});
