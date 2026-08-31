#!/usr/bin/env node
"use strict";

// Invoked by pi-acp as: <PI_ACP_PI_COMMAND> --mode rpc --no-themes

const fs = require("fs");
const readline = require("readline");

const logPath = process.env.PI_CONTRACT_LOG;
if (!logPath) {
  process.stderr.write("PI_CONTRACT_LOG is required\n");
  process.exit(2);
}

const state = { aborts: [], prompts: [] };
let pendingPrompt = null;
let settleTimer = null;

function persist() {
  fs.writeFileSync(logPath, JSON.stringify(state));
}

function respond(id, body) {
  process.stdout.write(`${JSON.stringify({ type: "response", id, ...body })}\n`);
}

function scheduleLateSettle(promptMsg) {
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = setTimeout(() => {
    if (pendingPrompt && pendingPrompt.id === promptMsg.id) {
      process.stdout.write(`${JSON.stringify({ type: "agent_settled" })}\n`);
      pendingPrompt = null;
      persist();
    }
  }, 800);
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  if (msg.type === "get_state") {
    respond(msg.id, {
      success: true,
      data: { sessionId: "contract-sess", sessionFile: null, messageCount: 0 },
    });
    return;
  }

  if (msg.type === "prompt") {
    pendingPrompt = msg;
    state.prompts.push(msg.id);
    persist();
    process.stdout.write(`${JSON.stringify({ type: "agent_start" })}\n`);
    scheduleLateSettle(msg);
    return;
  }

  if (msg.type === "abort") {
    if (settleTimer) clearTimeout(settleTimer);
    state.aborts.push(msg.id);
    persist();
    respond(msg.id, { success: true, data: {} });
    process.stdout.write(`${JSON.stringify({ type: "agent_settled" })}\n`);
    pendingPrompt = null;
  }
});

persist();
