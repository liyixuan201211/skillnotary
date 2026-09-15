import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

/** Run the CLI and return its exit code; a non-zero exit is not an error here. */
function run(args: string[]): number {
  try {
    execFileSync(process.execPath, [CLI, ...args], { stdio: "pipe" });
    return 0;
  } catch (error: unknown) {
    const status = (error as { status?: number | null }).status;
    return typeof status === "number" ? status : -1;
  }
}

test("an explicit help request succeeds; a bare invocation is a usage error", () => {
  // `--help` used to exit 2: the flag leaves no positional command, so the
  // explicit-help case fell into the no-command branch. That made the
  // documented smoke test `skillnotary --help` look like a failure.
  assert.equal(run(["--help"]), 0);
  assert.equal(run(["-h"]), 0);
  assert.equal(run(["help"]), 0);
  assert.equal(run(["--version"]), 0);
  assert.equal(run(["version"]), 0);
  assert.equal(run([]), 2, "no command at all is a usage error");
  assert.equal(run(["not-a-command"]), 2);
});
