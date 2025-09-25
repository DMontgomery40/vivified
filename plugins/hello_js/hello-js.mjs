#!/usr/bin/env node
import readline from "node:readline";
const meta = { name: "hello-js", version: "0.0.1", capabilities: ["demo"], requires_traits: [] };
let ENV = {}; let TRAITS = new Set();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
rl.on("line", (line) => {
  try {
    const req = JSON.parse(line); const { method, params } = req;
    if (method === "capabilities") return respond({ result: meta });
    if (method === "init") { ENV = (params && params.env) || {}; TRAITS = new Set(params?.traits || []); return respond({ result: true }); }
    if (method === "run") {
      const who = (params?.args && params.args[0]) || "world";
      console.log(`[vivi] hello from Node, ${who}!`);
      return respond({ result: 0 });
    }
    return respond({ error: `unknown method ${method}` });
  } catch (e) { return respond({ error: String(e) }); }
});
function respond(obj){ process.stdout.write(JSON.stringify(obj) + "\n"); }
