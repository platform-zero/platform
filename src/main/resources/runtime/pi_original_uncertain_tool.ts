import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";

// Installed only for the original Pi native case, never during restored startup.
// No model-supplied path or command reaches this one-use, case-local effect.
const expected = process.env.P0V3_UNCERTAIN_NONCE || "";
const directory = process.env.P0V3_UNCERTAIN_CASE_DIR || "";
if (!/^[a-f0-9]{32}$/.test(expected) ||
    !/^\/home\/dev\/\.pi\/qualified-uncertain-[a-f0-9]{32}$/.test(directory) ||
    path.basename(directory) !== `qualified-uncertain-${expected}`) {
  throw new Error("Original Pi uncertain-tool scope is not an exact case-owned path");
}

function saveOnce(name: string, body: object): string {
  const dest = path.join(directory, name);
  const bytes = Buffer.from(JSON.stringify(body) + "\n");
  if (bytes.length > 2048) throw new Error("Oversized original Pi tool journal");
  const fd = fs.openSync(dest, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return createHash("sha256").update(bytes).digest("hex");
}

export default function (pi: ExtensionAPI) {
  pi.registerTool(defineTool({
    name: "p0v3_original_uncertain_marker",
    label: "Original one-use uncertain marker",
    description: "Create the single bounded, synthetic original-only marker for the reviewed Pi no-replay test. Call once with the exact requested nonce; the process ends before acknowledging the tool result.",
    parameters: Type.Object({ nonce: Type.String({ pattern: "^[a-f0-9]{32}$" }) }),
    async execute(toolCallId, params) {
      if (params.nonce !== expected || !/^[A-Za-z0-9_-]{1,128}$/.test(toolCallId))
        throw new Error("Foreign original Pi tool attempt");
      const stat = fs.lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 ||
          stat.uid !== process.getuid()) throw new Error("Unsafe Pi case scope");
      const intentHash = saveOnce("tool-effect.intent.json", {
        schemaVersion: 1, nonce: expected, toolCallId,
        operation: "create-once-synthetic-local-marker", effect: "not-yet-attempted",
      });
      const markerHash = saveOnce("original-marker.txt", { nonce: expected });
      saveOnce("tool-effect.result.json", {
        schemaVersion: 1, nonce: expected, toolCallId, intentSha256: intentHash,
        markerSha256: markerHash, nativeAttempted: true,
        disposition: "effect-observed-before-tool-result-ack",
      });
      // The already-completed MODEL toolCall remains in Pi's real JSONL session.
      // There is intentionally no toolResult: the controller must independently
      // verify this one effect, the session and process exit before accepting it.
      process.kill(process.pid, "SIGKILL");
      throw new Error("SIGKILL was unexpectedly ignored; no tool ACK is valid");
    },
  }));
}
