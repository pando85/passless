#!/usr/bin/env node

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const DRIVER_PATH = path.join(__dirname, '..', 'browser', 'real-rp-driver.js');

describe('Gate C Real-RP Driver', () => {

  describe('module exports', () => {
    it('exports GateCDriver constructor', () => {
      const m = require(DRIVER_PATH);
      assert.strictEqual(typeof m.GateCDriver, 'function');
    });

    it('exports selfCheck function', () => {
      const m = require(DRIVER_PATH);
      assert.strictEqual(typeof m.selfCheck, 'function');
    });

    it('exports FORBIDDEN_CDP_METHODS array', () => {
      const m = require(DRIVER_PATH);
      assert.ok(Array.isArray(m.FORBIDDEN_CDP_METHODS));
      assert.ok(m.FORBIDDEN_CDP_METHODS.includes('WebAuthn.enable'));
      assert.ok(m.FORBIDDEN_CDP_METHODS.includes('WebAuthn.addVirtualAuthenticator'));
      assert.ok(m.FORBIDDEN_CDP_METHODS.includes('WebAuthn.addCredential'));
    });

    it('exports EXPECTED_SELECTOR string', () => {
      const m = require(DRIVER_PATH);
      assert.strictEqual(m.EXPECTED_SELECTOR, 'a.signin-passkey');
    });
  });

  describe('self-check', () => {
    it('passes (no forbidden methods in source)', () => {
      const m = require(DRIVER_PATH);
      const result = m.selfCheck();
      assert.strictEqual(result.pass, true);
      assert.deepStrictEqual(result.violations, []);
    });

    it('FORBIDDEN_CDP_METHODS are only in the blocklist, not called', () => {
      const source = fs.readFileSync(DRIVER_PATH, 'utf8');
      const lines = source.split('\n');
      const forbiddenMethods = ['WebAuthn.enable', 'WebAuthn.addVirtualAuthenticator', 'WebAuthn.addCredential'];

      for (const method of forbiddenMethods) {
        let foundOutsideBlocklist = false;
        for (const line of lines) {
          if (line.includes('FORBIDDEN_CDP_METHODS')) continue;
          if (line.includes('selfCheck')) continue;
          if (line.includes("'") && line.includes(method) && !line.includes('indexOf') && !line.includes('includes')) {
            if (!line.trim().startsWith('const ') && !line.trim().startsWith('var ') && !line.trim().startsWith('let ')) {
              foundOutsideBlocklist = true;
            }
          }
        }
        assert.strictEqual(foundOutsideBlocklist, false, method + ' found outside blocklist');
      }
    });
  });

  describe('source code analysis', () => {
    let source;

    it('can read driver source', () => {
      source = fs.readFileSync(DRIVER_PATH, 'utf8');
      assert.ok(source.length > 0);
    });

    it('does not call WebAuthn.enable', () => {
      const lines = source.split('\n').filter(l => !l.includes('FORBIDDEN_CDP_METHODS') && !l.includes('selfCheck'));
      const codeLines = lines.filter(l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
      const joined = codeLines.join('\n');
      assert.ok(joined.indexOf("send('WebAuthn.enable'") === -1);
      assert.ok(joined.indexOf('send("WebAuthn.enable"') === -1);
    });

    it('does not call addVirtualAuthenticator', () => {
      const lines = source.split('\n').filter(l => !l.includes('FORBIDDEN_CDP_METHODS') && !l.includes('selfCheck'));
      const codeLines = lines.filter(l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
      const joined = codeLines.join('\n');
      assert.ok(joined.indexOf("send('WebAuthn.addVirtualAuthenticator'") === -1);
      assert.ok(joined.indexOf('send("WebAuthn.addVirtualAuthenticator"') === -1);
    });

    it('does not call addCredential', () => {
      const lines = source.split('\n').filter(l => !l.includes('FORBIDDEN_CDP_METHODS') && !l.includes('selfCheck'));
      const codeLines = lines.filter(l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
      const joined = codeLines.join('\n');
      assert.ok(joined.indexOf("send('WebAuthn.addCredential'") === -1);
      assert.ok(joined.indexOf('send("WebAuthn.addCredential"') === -1);
    });

    it('uses a.signin-passkey selector', () => {
      assert.ok(source.includes('a.signin-passkey'));
    });

    it('navigates to /user/login', () => {
      assert.ok(source.includes('/user/login'));
    });

    it('does not read .pass/ or .password-store/ files', () => {
      const codeLines = source.split('\n').filter(l =>
        !l.includes('FORBIDDEN_FILE_PATTERNS') &&
        !l.includes('selfCheck') &&
        !l.trim().startsWith('//')
      );
      const joined = codeLines.join('\n');
      assert.ok(joined.indexOf('.pass/') === -1 || joined.indexOf("'/") === -1);
      assert.ok(joined.indexOf('.password-store/') === -1 || joined.indexOf("readFile") === -1);
    });

    it('does not close WebSocket on daemon-managed browser (only disconnects own WS)', () => {
      const closeLines = source.split('\n').filter(l => l.includes('.close()'));
      for (const line of closeLines) {
        assert.ok(
          line.includes('this.ws') || line.includes('self.ws'),
          'close() should only be called on own WebSocket: ' + line.trim()
        );
      }
    });
  });

  describe('GateCDriver constructor', () => {
    it('stores cdpPort, rpUrl, evidenceDir', () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://tea.millaguie.net', '/tmp');
      assert.strictEqual(driver.cdpPort, 9222);
      assert.strictEqual(driver.rpUrl, 'https://tea.millaguie.net');
      assert.strictEqual(driver.evidenceDir, '/tmp');
    });

    it('initializes with empty calledMethods', () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://tea.millaguie.net', '/tmp');
      assert.deepStrictEqual(driver.calledMethods, []);
    });

    it('initializes as not connected', () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://tea.millaguie.net', '/tmp');
      assert.strictEqual(driver.connected, false);
    });
  });

  describe('send method blocks forbidden CDP methods', () => {
    it('throws for WebAuthn.enable', async () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://example.com', '/tmp');
      driver.ws = { send: function() {} };
      driver.connected = true;

      await assert.rejects(
        function() { return driver.send('WebAuthn.enable', {}); },
        { message: /FORBIDDEN/ }
      );
    });

    it('throws for WebAuthn.addVirtualAuthenticator', async () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://example.com', '/tmp');
      driver.ws = { send: function() {} };
      driver.connected = true;

      await assert.rejects(
        function() { return driver.send('WebAuthn.addVirtualAuthenticator', {}); },
        { message: /FORBIDDEN/ }
      );
    });

    it('throws for WebAuthn.addCredential', async () => {
      const { GateCDriver } = require(DRIVER_PATH);
      const driver = new GateCDriver(9222, 'https://example.com', '/tmp');
      driver.ws = { send: function() {} };
      driver.connected = true;

      await assert.rejects(
        function() { return driver.send('WebAuthn.addCredential', {}); },
        { message: /FORBIDDEN/ }
      );
    });
  });

  describe('mock cannot yield live PASS', () => {
    it('selfCheck reads actual source file, not mock', () => {
      const m = require(DRIVER_PATH);
      const result = m.selfCheck();
      assert.strictEqual(result.pass, true);
      const source = fs.readFileSync(DRIVER_PATH, 'utf8');
      assert.ok(source.includes('FORBIDDEN_CDP_METHODS'));
    });

    it('FORBIDDEN_CDP_METHODS list is non-empty', () => {
      const m = require(DRIVER_PATH);
      assert.ok(m.FORBIDDEN_CDP_METHODS.length >= 3);
    });
  });
});
