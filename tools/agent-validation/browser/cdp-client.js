#!/usr/bin/env node
/**
 * Real Chrome DevTools Protocol client using WebSocket
 * Uses Node 22+ global WebSocket (no external dependencies)
 */

'use strict';

class CDPClient {
  constructor(wsUrl, timeoutMs = 10000) {
    this.wsUrl = wsUrl;
    this.timeoutMs = timeoutMs;
    this.ws = null;
    this.messageId = 0;
    this.pendingRequests = new Map();
    this.connected = false;
  }

  async connect() {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`CDP connection timeout after ${this.timeoutMs}ms`));
      }, this.timeoutMs);

      try {
        this.ws = new WebSocket(this.wsUrl);

        this.ws.onopen = () => {
          clearTimeout(timeout);
          this.connected = true;
          resolve();
        };

        this.ws.onerror = (err) => {
          clearTimeout(timeout);
          reject(new Error(`CDP WebSocket error: ${err.message || 'unknown'}`));
        };

        this.ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.id !== undefined && this.pendingRequests.has(msg.id)) {
              const { resolve, reject, timer } = this.pendingRequests.get(msg.id);
              clearTimeout(timer);
              this.pendingRequests.delete(msg.id);

              if (msg.error) {
                reject(new Error(`CDP error: ${msg.error.message || JSON.stringify(msg.error)}`));
              } else {
                resolve(msg.result);
              }
            }
          } catch (err) {
            // Ignore parse errors for events
          }
        };

        this.ws.onclose = () => {
          this.connected = false;
          for (const [id, { reject, timer }] of this.pendingRequests) {
            clearTimeout(timer);
            reject(new Error('CDP connection closed'));
          }
          this.pendingRequests.clear();
        };
      } catch (err) {
        clearTimeout(timeout);
        reject(err);
      }
    });
  }

  async send(method, params = {}) {
    if (!this.connected || !this.ws) {
      throw new Error('CDP not connected');
    }

    const id = ++this.messageId;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`CDP request timeout after ${this.timeoutMs}ms: ${method}`));
      }, this.timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });

      const msg = JSON.stringify({ id, method, params });
      try {
        this.ws.send(msg);
      } catch (err) {
        clearTimeout(timer);
        this.pendingRequests.delete(id);
        reject(err);
      }
    });
  }

  async evaluate(expression, returnByValue = true) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue,
      awaitPromise: true
    });

    if (result.exceptionDetails) {
      throw new Error(`JS exception: ${result.exceptionDetails.text || JSON.stringify(result.exceptionDetails)}`);
    }

    return result.result;
  }

  async navigate(url) {
    const result = await this.send('Page.navigate', { url });
    if (result.errorText) {
      throw new Error(`Navigation failed: ${result.errorText}`);
    }
    return result;
  }

  async close() {
    if (this.ws) {
      try {
        this.ws.close();
      } catch (e) {
        // Ignore close errors
      }
      this.ws = null;
      this.connected = false;
    }
  }
}

async function getPageTarget(cdpPort) {
  const response = await fetch(`http://127.0.0.1:${cdpPort}/json/list`);
  if (!response.ok) {
    throw new Error(`Failed to list CDP targets: ${response.status}`);
  }

  const targets = await response.json();
  const page = targets.find(t => t.type === 'page');
  if (!page) {
    throw new Error('No page target found');
  }

  return page.webSocketDebuggerUrl;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Usage: cdp-client.js <command> [args...]');
    console.error('Commands: evaluate <expr>, navigate <url>, health');
    process.exit(1);
  }

  const command = args[0];
  const cdpPort = process.env.AV_CDP_PORT || '9222';
  const timeoutMs = parseInt(process.env.AV_CDP_TIMEOUT || '10000', 10);

  let client;
  try {
    const wsUrl = await getPageTarget(cdpPort);
    client = new CDPClient(wsUrl, timeoutMs);
    await client.connect();

    let result;
    switch (command) {
      case 'health':
        result = { status: 'ok', connected: true };
        break;

      case 'evaluate':
        if (args.length < 2) {
          throw new Error('evaluate requires expression argument');
        }
        const expression = args[1];
        const evalResult = await client.evaluate(expression);
        result = {
          type: evalResult.type,
          value: evalResult.value,
          description: evalResult.description
        };
        break;

      case 'navigate':
        if (args.length < 2) {
          throw new Error('navigate requires URL argument');
        }
        const url = args[1];
        await client.navigate(url);
        result = { status: 'ok', navigated: url };
        break;

      default:
        throw new Error(`Unknown command: ${command}`);
    }

    console.log(JSON.stringify(result));
    process.exit(0);
  } catch (err) {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  } finally {
    if (client) {
      await client.close();
    }
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error(err.message);
    process.exit(1);
  });
}

module.exports = { CDPClient, getPageTarget };
