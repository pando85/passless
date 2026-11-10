'use strict';
// Minimal MCP stdio client: newline-delimited JSON-RPC 2.0 (initialize, tools/list, tools/call).
// Enough to drive `@playwright/mcp` against a running browser (`--cdp-endpoint`), the way agents do.

const path = require('node:path');
const { spawn } = require('node:child_process');

const { HARNESS_ROOT } = require('./paths');

const PROTOCOL_VERSION = '2025-06-18';

class McpClient {
  constructor(child) {
    this.child = child;
    this.nextId = 1;
    this.pending = new Map();
    this.stderr = '';
    this.buf = '';
    child.stdout.on('data', d => this._onData(d));
    child.stderr.on('data', d => { if (this.stderr.length < 20000) this.stderr += d; });
    child.once('exit', (code, sig) => {
      for (const { reject } of this.pending.values()) reject(new Error(`MCP server exited (${code ?? sig}): ${this.stderr.slice(-400)}`));
      this.pending.clear();
    });
  }

  /** @param {{command:string,args?:string[],env?:object,cwd?:string}} o */
  static start({ command, args = [], env, cwd }) {
    if (!env) throw new Error('McpClient.start requires an explicit env (never inherit process.env: it would leak the real HOME/XDG)');
    const child = spawn(command, args, { env, cwd, stdio: ['pipe', 'pipe', 'pipe'], detached: true });
    return new McpClient(child);
  }

  _onData(chunk) {
    this.buf += chunk.toString('utf8');
    let i;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; } // non-protocol noise on stdout
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(Object.assign(new Error(msg.error.message || 'MCP error'), { rpc: msg.error })); else resolve(msg.result);
      }
    }
  }

  _send(obj) { this.child.stdin.write(JSON.stringify(obj) + '\n'); }

  request(method, params, timeoutMs = 60000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(`MCP ${method} timed out after ${timeoutMs}ms: ${this.stderr.slice(-300)}`)); }, timeoutMs);
      this.pending.set(id, { resolve: v => { clearTimeout(t); resolve(v); }, reject: e => { clearTimeout(t); reject(e); } });
      this._send({ jsonrpc: '2.0', id, method, params });
    });
  }

  notify(method, params) { this._send({ jsonrpc: '2.0', method, params }); }

  async initialize() {
    const res = await this.request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'passless-agent-e2e', version: '0.0.0' } });
    this.notify('notifications/initialized', {});
    return res;
  }
  async listTools() { return (await this.request('tools/list', {})).tools; }
  callTool(name, args = {}, timeoutMs = 90000) { return this.request('tools/call', { name, arguments: args }, timeoutMs); }

  close() {
    try { this.child.stdin.end(); } catch { /* closed */ }
    try { process.kill(-this.child.pid, 'SIGKILL'); } catch { /* gone */ }
  }
}

/** Command line for the pinned local `@playwright/mcp` (see package.json / package-lock.json). */
function playwrightMcpCommand({ cdpUrl, extraArgs = [] }) {
  return { command: process.execPath, args: [path.join(HARNESS_ROOT, 'node_modules', '@playwright', 'mcp', 'cli.js'), '--cdp-endpoint', cdpUrl, ...extraArgs] };
}

module.exports = { McpClient, playwrightMcpCommand };
