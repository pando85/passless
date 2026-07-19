#!/usr/bin/env node
/**
 * Mock CDP WebSocket server for testing
 * Implements minimal Chrome DevTools Protocol with proper WebSocket handling
 */

'use strict';

const http = require('http');
const crypto = require('crypto');

class MockCDPServer {
  constructor(port = 9222) {
    this.port = port;
    this.server = null;
    this.wsConnections = new Set();
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        if (req.url === '/json/version') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            Browser: 'MockCDP/1.0',
            'Protocol-Version': '1.3',
            webSocketDebuggerUrl: `ws://127.0.0.1:${this.port}/devtools/browser/mock`
          }));
        } else if (req.url === '/json/list') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([
            {
              type: 'page',
              id: 'mock-page-1',
              title: 'Mock Page',
              url: 'about:blank',
              webSocketDebuggerUrl: `ws://127.0.0.1:${this.port}/devtools/page/mock-page-1`
            }
          ]));
        } else {
          res.writeHead(404);
          res.end('Not found');
        }
      });

      this.server.on('upgrade', (req, socket, head) => {
        if (req.url.startsWith('/devtools/')) {
          this.handleWebSocketUpgrade(req, socket, head);
        } else {
          socket.destroy();
        }
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        resolve();
      });

      this.server.on('error', reject);
    });
  }

  handleWebSocketUpgrade(req, socket, head) {
    const key = req.headers['sec-websocket-key'];
    const acceptKey = crypto
      .createHash('sha1')
      .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');

    const response = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey}`,
      '',
      ''
    ].join('\r\n');

    socket.write(response);
    this.wsConnections.add(socket);

    let buffer = Buffer.alloc(0);

    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);

      while (buffer.length >= 2) {
        const frame = this.decodeFrame(buffer);
        if (!frame) break;

        buffer = buffer.slice(frame.totalLength);

        if (frame.payload) {
          try {
            const msg = JSON.parse(frame.payload);
            this.handleMessage(socket, msg);
          } catch (err) {
            // Ignore parse errors
          }
        }
      }
    });

    socket.on('close', () => {
      this.wsConnections.delete(socket);
    });

    socket.on('error', () => {
      this.wsConnections.delete(socket);
    });
  }

  decodeFrame(buffer) {
    if (buffer.length < 2) return null;

    const firstByte = buffer[0];
    const secondByte = buffer[1];

    const opcode = firstByte & 0x0f;
    if (opcode === 0x08) { // Close frame
      return { totalLength: 2, payload: null };
    }
    if (opcode !== 0x01) return null; // Text frame only

    let payloadLength = secondByte & 0x7f;
    let offset = 2;

    if (payloadLength === 126) {
      if (buffer.length < 4) return null;
      payloadLength = buffer.readUInt16BE(2);
      offset = 4;
    } else if (payloadLength === 127) {
      if (buffer.length < 10) return null;
      payloadLength = Number(buffer.readBigUInt64BE(2));
      offset = 10;
    }

    const masked = (secondByte & 0x80) !== 0;
    if (masked) {
      if (buffer.length < offset + 4) return null;
      const mask = buffer.slice(offset, offset + 4);
      offset += 4;

      if (buffer.length < offset + payloadLength) return null;
      const payload = Buffer.alloc(payloadLength);
      for (let i = 0; i < payloadLength; i++) {
        payload[i] = buffer[offset + i] ^ mask[i % 4];
      }

      return {
        totalLength: offset + payloadLength,
        payload: payload.toString('utf8')
      };
    } else {
      if (buffer.length < offset + payloadLength) return null;
      return {
        totalLength: offset + payloadLength,
        payload: buffer.slice(offset, offset + payloadLength).toString('utf8')
      };
    }
  }

  encodeFrame(message) {
    const payload = Buffer.from(message, 'utf8');
    const length = payload.length;

    let header;
    if (length < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81; // FIN + Text frame
      header[1] = length;
    } else if (length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(length), 2);
    }

    return Buffer.concat([header, payload]);
  }

  handleMessage(socket, msg) {
    const { id, method, params } = msg;

    let result = {};

    switch (method) {
      case 'Runtime.evaluate':
        const expression = params.expression || '';
        try {
          // Mock evaluation - return the expression result
          if (expression.includes('true')) {
            result = { result: { type: 'boolean', value: true } };
          } else if (expression.includes('REGISTER OK')) {
            result = { result: { type: 'string', value: 'REGISTER OK' } };
          } else if (expression.includes('AUTH OK')) {
            result = { result: { type: 'string', value: 'AUTH OK' } };
          } else {
            result = { result: { type: 'undefined' } };
          }
        } catch (err) {
          result = { exceptionDetails: { text: err.message } };
        }
        break;

      case 'Page.navigate':
        result = { frameId: 'mock-frame-1' };
        break;

      default:
        result = { error: { message: `Unknown method: ${method}` } };
    }

    const response = JSON.stringify({ id, result });
    socket.write(this.encodeFrame(response));
  }

  async stop() {
    for (const socket of this.wsConnections) {
      socket.destroy();
    }
    this.wsConnections.clear();

    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => resolve());
      });
    }
  }
}

if (require.main === module) {
  const port = parseInt(process.argv[2] || '9222', 10);
  const server = new MockCDPServer(port);

  server.start().then(() => {
    console.log(`Mock CDP server listening on port ${port}`);
  }).catch(err => {
    console.error('Failed to start mock CDP server:', err);
    process.exit(1);
  });

  process.on('SIGINT', async () => {
    await server.stop();
    process.exit(0);
  });
}

module.exports = { MockCDPServer };
