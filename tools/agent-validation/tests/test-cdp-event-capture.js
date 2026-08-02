#!/usr/bin/env node

'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { CDPEventCapture, DIALOG_METHODS } = require('../browser/cdp-event-capture.js');
const { MockCDPServer } = require('../browser/mock-cdp-server.js');

const TEST_PORT = 19333;

describe('CDPEventCapture', () => {

  describe('DIALOG_METHODS', () => {
    it('contains expected dialog methods', () => {
      assert.ok(DIALOG_METHODS.has('Page.javascriptDialogOpening'));
      assert.ok(DIALOG_METHODS.has('Page.javascriptDialogClosed'));
    });

    it('does not contain non-dialog methods', () => {
      assert.ok(!DIALOG_METHODS.has('Page.navigate'));
      assert.ok(!DIALOG_METHODS.has('Runtime.evaluate'));
    });
  });

  describe('report generation from JSONL', () => {
    let tmpDir;

    before(() => {
      tmpDir = fs.mkdtempSync('/tmp/cc-event-test-');
    });

    after(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('produces correct report for empty events file', () => {
      const emptyFile = path.join(tmpDir, 'empty.jsonl');
      fs.writeFileSync(emptyFile, '');

      const lines = fs.readFileSync(emptyFile, 'utf8').trim().split('\n').filter(Boolean);
      assert.strictEqual(lines.length, 0);
    });

    it('counts dialog events correctly', () => {
      const eventsFile = path.join(tmpDir, 'events-with-dialogs.jsonl');
      const events = [
        { method: 'Page.frameNavigated', params: { frame: {} } },
        { method: 'Page.javascriptDialogOpening', params: { message: 'test alert' } },
        { method: 'Runtime.consoleAPICalled', params: { type: 'log', args: [] } },
        { method: 'Page.javascriptDialogClosed', params: {} },
        { method: 'Log.entryAdded', params: { entry: { level: 'info', text: 'test' } } },
      ];

      fs.writeFileSync(eventsFile, events.map(e => JSON.stringify(e)).join('\n') + '\n');

      const lines = fs.readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean);
      let dialogCount = 0;
      const byDomain = { page: 0, runtime: 0, log: 0 };

      for (const line of lines) {
        const e = JSON.parse(line);
        if (e.method.startsWith('Page.')) byDomain.page++;
        if (e.method.startsWith('Runtime.')) byDomain.runtime++;
        if (e.method.startsWith('Log.')) byDomain.log++;
        if (DIALOG_METHODS.has(e.method)) dialogCount++;
      }

      assert.strictEqual(dialogCount, 2);
      assert.strictEqual(byDomain.page, 3);
      assert.strictEqual(byDomain.runtime, 1);
      assert.strictEqual(byDomain.log, 1);
    });

    it('detects zero dialogs in clean events', () => {
      const eventsFile = path.join(tmpDir, 'clean-events.jsonl');
      const events = [
        { method: 'Page.frameNavigated', params: {} },
        { method: 'Page.loadEventFired', params: {} },
        { method: 'Runtime.executionContextCreated', params: {} },
        { method: 'Log.entryAdded', params: { entry: { level: 'info', text: 'ok' } } },
      ];

      fs.writeFileSync(eventsFile, events.map(e => JSON.stringify(e)).join('\n') + '\n');

      const lines = fs.readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean);
      let dialogCount = 0;
      for (const line of lines) {
        const e = JSON.parse(line);
        if (DIALOG_METHODS.has(e.method)) dialogCount++;
      }

      assert.strictEqual(dialogCount, 0);
    });

    it('counts runtime exceptions', () => {
      const eventsFile = path.join(tmpDir, 'exception-events.jsonl');
      const events = [
        { method: 'Runtime.exceptionThrown', params: { exceptionDetails: { text: 'Error' } } },
        { method: 'Runtime.consoleAPICalled', params: { type: 'error', args: [] } },
        { method: 'Runtime.consoleAPICalled', params: { type: 'log', args: [] } },
      ];

      fs.writeFileSync(eventsFile, events.map(e => JSON.stringify(e)).join('\n') + '\n');

      const lines = fs.readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean);
      let runtimeExceptions = 0;
      for (const line of lines) {
        const e = JSON.parse(line);
        if (e.method === 'Runtime.exceptionThrown') runtimeExceptions++;
        if (e.method === 'Runtime.consoleAPICalled' && e.params && e.params.type === 'error') runtimeExceptions++;
      }

      assert.strictEqual(runtimeExceptions, 2);
    });

    it('counts log errors', () => {
      const eventsFile = path.join(tmpDir, 'log-errors.jsonl');
      const events = [
        { method: 'Log.entryAdded', params: { level: 'error', text: 'fail' } },
        { method: 'Log.entryAdded', params: { level: 'severe', text: 'critical' } },
        { method: 'Log.entryAdded', params: { level: 'info', text: 'ok' } },
        { method: 'Log.entryAdded', params: { level: 'warning', text: 'warn' } },
      ];

      fs.writeFileSync(eventsFile, events.map(e => JSON.stringify(e)).join('\n') + '\n');

      const lines = fs.readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean);
      let logErrors = 0;
      for (const line of lines) {
        const e = JSON.parse(line);
        if (e.params && (e.params.level === 'error' || e.params.level === 'severe')) logErrors++;
      }

      assert.strictEqual(logErrors, 2);
    });
  });

  describe('event capture with mock CDP server', () => {
    let mockServer;
    let tmpDir;

    before(async () => {
      tmpDir = fs.mkdtempSync('/tmp/cc-capture-test-');
      mockServer = new MockCDPServer(TEST_PORT);
      await mockServer.start();
    });

    after(async () => {
      if (mockServer) await mockServer.stop();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('CDPEventCapture can be constructed', () => {
      const capture = new CDPEventCapture(TEST_PORT, {
        output: path.join(tmpDir, 'test.jsonl'),
        domains: 'Page,Runtime,Log',
      });
      assert.strictEqual(capture.cdpPort, TEST_PORT);
      assert.strictEqual(capture.dialogCount, 0);
      assert.deepStrictEqual(capture.events, []);
    });

    it('generateReport returns correct structure for empty capture', () => {
      const capture = new CDPEventCapture(TEST_PORT, {
        output: path.join(tmpDir, 'test2.jsonl'),
      });
      const report = capture.generateReport();
      assert.strictEqual(report.total_events, 0);
      assert.strictEqual(report.js_dialog_events, 0);
      assert.strictEqual(report.js_dialog_assertion, 'zero_js_dialogs');
      assert.ok(report.dialog_note);
      assert.strictEqual(report.by_domain.page, 0);
      assert.strictEqual(report.by_domain.runtime, 0);
      assert.strictEqual(report.by_domain.log, 0);
    });

    it('_handleEvent increments dialog count for dialog methods', () => {
      const capture = new CDPEventCapture(TEST_PORT, {
        output: path.join(tmpDir, 'test3.jsonl'),
      });

      capture._handleEvent({ method: 'Page.javascriptDialogOpening', params: { message: 'test' } });
      assert.strictEqual(capture.dialogCount, 1);

      capture._handleEvent({ method: 'Page.frameNavigated', params: {} });
      assert.strictEqual(capture.dialogCount, 1);

      capture._handleEvent({ method: 'Page.javascriptDialogClosed', params: {} });
      assert.strictEqual(capture.dialogCount, 2);
    });

    it('_handleEvent writes events to output file', () => {
      const outputFile = path.join(tmpDir, 'test4.jsonl');
      const capture = new CDPEventCapture(TEST_PORT, { output: outputFile });

      capture._handleEvent({ method: 'Page.loadEventFired', params: {} });
      capture._handleEvent({ method: 'Runtime.executionContextCreated', params: {} });

      const lines = fs.readFileSync(outputFile, 'utf8').trim().split('\n').filter(Boolean);
      assert.strictEqual(lines.length, 2);

      const first = JSON.parse(lines[0]);
      assert.strictEqual(first.method, 'Page.loadEventFired');
      assert.ok(first.timestamp);
    });

    it('generateReport reflects accumulated events', () => {
      const capture = new CDPEventCapture(TEST_PORT, {
        output: path.join(tmpDir, 'test5.jsonl'),
      });

      capture._handleEvent({ method: 'Page.loadEventFired', params: {} });
      capture._handleEvent({ method: 'Runtime.exceptionThrown', params: {} });
      capture._handleEvent({ method: 'Log.entryAdded', params: { level: 'error' } });
      capture._handleEvent({ method: 'Page.javascriptDialogOpening', params: {} });

      const report = capture.generateReport();
      assert.strictEqual(report.total_events, 4);
      assert.strictEqual(report.js_dialog_events, 1);
      assert.strictEqual(report.js_dialog_assertion, 'js_dialogs_detected');
      assert.strictEqual(report.by_domain.page, 2);
      assert.strictEqual(report.by_domain.runtime, 1);
      assert.strictEqual(report.by_domain.log, 1);
      assert.strictEqual(report.runtime_exceptions, 1);
    });
  });
});
