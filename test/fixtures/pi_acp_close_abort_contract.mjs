#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [adapterRoot, mockPiPath, contractLogPath, mode] = process.argv.slice(2);

if (!adapterRoot || !mockPiPath || !contractLogPath || !mode) {
  process.stderr.write(
    "usage: pi_acp_close_abort_contract.mjs <adapterRoot> <mockPi> <logPath> patched|oracle\n",
  );
  process.exit(2);
}

const bundlePath = join(adapterRoot, "node_modules/pi-acp/dist/index.js");
const adapterEntry = bundlePath;
let bundle = readFileSync(bundlePath, "utf8");

if (mode === "oracle") {
  bundle = bundle.replace(
    "    const session = this.sessions.maybeGet(params.sessionId);\n    if (session) await session.cancel();\n    this.sessions.close(params.sessionId);",
    "    this.sessions.close(params.sessionId);",
  );
  writeFileSync(bundlePath, bundle);
}

writeFileSync(contractLogPath, JSON.stringify({ aborts: [], prompts: [] }));

const cwd = join(adapterRoot, "session-cwd");
const env = {
  ...process.env,
  PI_CONTRACT_LOG: contractLogPath,
  PI_ACP_PI_COMMAND: mockPiPath,
  PI_CODING_AGENT_DIR: join(adapterRoot, "pi-home"),
};

const child = spawn(process.execPath, [adapterEntry], {
  cwd,
  env,
  stdio: ["pipe", "pipe", "pipe"],
});

let nextId = 1;
const pending = new Map();

function send(method, params = {}) {
  const id = nextId++;
  const frame = { jsonrpc: "2.0", id, method, params };
  child.stdin.write(`${JSON.stringify(frame)}\n`);
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
  });
}

createInterface({ input: child.stdout }).on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id !== undefined && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(msg.error);
    else resolve(msg.result ?? {});
  }
});

const result = { mode, abortCount: null, stopReason: null, closeOk: false };

try {
  await send("initialize", {
    protocolVersion: 1,
    clientCapabilities: {},
    clientInfo: { name: "contract-fixture", version: "1" },
  });

  const created = await send("session/new", { cwd, mcpServers: [] });
  const sessionId = created.sessionId;

  const promptPromise = send("session/prompt", {
    sessionId,
    prompt: [{ type: "text", text: "stall for close contract" }],
  });

  await new Promise((resolve) => setTimeout(resolve, 150));

  await send("session/close", { sessionId });
  result.closeOk = true;

  const promptResult = await Promise.race([
    promptPromise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("prompt timed out")), 5000),
    ),
  ]);

  result.stopReason = promptResult.stopReason;

  const log = JSON.parse(readFileSync(contractLogPath, "utf8"));
  result.abortCount = log.aborts.length;

  process.stdout.write(`${JSON.stringify(result)}\n`);
  child.kill("SIGTERM");
  process.exit(0);
} catch (error) {
  result.error = String(error?.message ?? error);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  child.kill("SIGKILL");
  process.exit(1);
}
