#!/usr/bin/env node

'use strict';

const { CDPClient, getPageTarget } = require('./cdp-client.js');

const DOMAINS = ['Page', 'Runtime', 'Log'];

const DIALOG_METHODS = new Set([
  'Page.javascriptDialogOpening',
  'Page.javascriptDialogClosed',
  'Page.dialogOpening',
]);

class CDPEventCapture {
  constructor(cdpPort, options = {}) {
    this.cdpPort = cdpPort;
    this.outputFile = options.output || 'cdp-events.jsonl';
    const rawDomains = options.domains || DOMAINS;
    this.domains = Array.isArray(rawDomains) ? rawDomains : rawDomains.split(',').map(d => d.trim());
    this.events = [];
    this.dialogCount = 0;
    this.client = null;
    this.fs = require('fs');
    this.running = false;
  }

  async start() {
    const wsUrl = await getPageTarget(this.cdpPort);
    this.client = new CDPClient(wsUrl, 30000);
    await this.client.connect();

    this.client.ws.on('message', (event) => {
      try {
        const msg = JSON.parse(typeof event === 'string' ? event : event.data);
        if (msg.id !== undefined) return;
        if (!msg.method) return;
        this._handleEvent(msg);
      } catch (_) {
      }
    });

    for (const domain of this.domains) {
      try {
        await this.client.send(`${domain}.enable`, {});
      } catch (err) {
        process.stderr.write(`Warning: could not enable ${domain}: ${err.message}\n`);
      }
    }

    this.running = true;

    process.on('SIGINT', () => this.stop());
    process.on('SIGTERM', () => this.stop());
  }

  _handleEvent(msg) {
    const entry = {
      timestamp: new Date().toISOString(),
      method: msg.method,
      params: msg.params || {},
    };

    if (DIALOG_METHODS.has(msg.method)) {
      this.dialogCount++;
      entry._dialog = true;
    }

    this.events.push(entry);

    const line = JSON.stringify(entry) + '\n';
    try {
      this.fs.appendFileSync(this.outputFile, line);
    } catch (_) {
    }
  }

  async stop() {
    this.running = false;

    const report = this.generateReport();
    const reportFile = this.outputFile.replace(/\.jsonl$/, '-report.json');
    try {
      this.fs.writeFileSync(reportFile, JSON.stringify(report, null, 2) + '\n');
    } catch (_) {
    }

    if (this.client) {
      await this.client.close();
    }

    process.stdout.write(JSON.stringify(report) + '\n');
    process.exit(0);
  }

  generateReport() {
    const pageEvents = this.events.filter(e => e.method.startsWith('Page.'));
    const runtimeEvents = this.events.filter(e => e.method.startsWith('Runtime.'));
    const logEvents = this.events.filter(e => e.method.startsWith('Log.'));

    const runtimeExceptions = runtimeEvents.filter(e =>
      e.method === 'Runtime.exceptionThrown' || e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error'
    );

    const logErrors = logEvents.filter(e =>
      e.params && (e.params.level === 'error' || e.params.level === 'severe')
    );

    return {
      generated_at: new Date().toISOString(),
      total_events: this.events.length,
      by_domain: {
        page: pageEvents.length,
        runtime: runtimeEvents.length,
        log: logEvents.length,
      },
      js_dialog_events: this.dialogCount,
      js_dialog_assertion: this.dialogCount === 0 ? 'zero_js_dialogs' : 'js_dialogs_detected',
      dialog_note: 'ancillary_evidence_only_native_chooser_not_js_dialog',
      runtime_exceptions: runtimeExceptions.length,
      log_errors: logErrors.length,
      events_file: this.outputFile,
    };
  }
}

async function runCapture(args) {
  let outputFile = 'cdp-events.jsonl';
  let domains = DOMAINS.join(',');

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      outputFile = args[++i];
    } else if (args[i] === '--domains' && args[i + 1]) {
      domains = args[++i];
    }
  }

  const cdpPort = process.env.AV_CDP_PORT || '9222';
  const capture = new CDPEventCapture(cdpPort, { output: outputFile, domains });
  await capture.start();
}

async function runReport(args) {
  let inputFile = 'cdp-events.jsonl';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      inputFile = args[++i];
    }
  }

  const fs = require('fs');
  if (!fs.existsSync(inputFile)) {
    process.stdout.write(JSON.stringify({
      total_events: 0,
      js_dialog_events: 0,
      js_dialog_assertion: 'no_data',
      dialog_note: 'ancillary_evidence_only_native_chooser_not_js_dialog',
      by_domain: { page: 0, runtime: 0, log: 0 },
      runtime_exceptions: 0,
      log_errors: 0,
    }) + '\n');
    return;
  }

  const lines = fs.readFileSync(inputFile, 'utf8').trim().split('\n').filter(Boolean);
  const events = lines.map(l => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);

  let dialogCount = 0;
  const byDomain = { page: 0, runtime: 0, log: 0 };
  let runtimeExceptions = 0;
  let logErrors = 0;

  for (const e of events) {
    if (e.method && e.method.startsWith('Page.')) byDomain.page++;
    if (e.method && e.method.startsWith('Runtime.')) byDomain.runtime++;
    if (e.method && e.method.startsWith('Log.')) byDomain.log++;
    if (DIALOG_METHODS.has(e.method)) dialogCount++;
    if (e.method === 'Runtime.exceptionThrown') runtimeExceptions++;
    if (e.method === 'Runtime.consoleAPICalled' && e.params && e.params.type === 'error') runtimeExceptions++;
    if (e.params && (e.params.level === 'error' || e.params.level === 'severe')) logErrors++;
  }

  process.stdout.write(JSON.stringify({
    generated_at: new Date().toISOString(),
    total_events: events.length,
    by_domain: byDomain,
    dialog_events: dialogCount,
    js_dialog_assertion: dialogCount === 0 ? 'zero_js_dialogs' : 'js_dialogs_detected',
    dialog_note: 'ancillary_evidence_only_native_chooser_not_js_dialog',
    runtime_exceptions: runtimeExceptions,
    log_errors: logErrors,
    events_file: inputFile,
  }, null, 2) + '\n');
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'capture';

  try {
    switch (command) {
      case 'capture':
        await runCapture(args.slice(1));
        break;
      case 'report':
        await runReport(args.slice(1));
        break;
      default:
        process.stderr.write(`Usage: cdp-event-capture.js <capture|report> [--output FILE] [--domains Page,Runtime,Log]\n`);
        process.exit(1);
    }
  } catch (err) {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(err => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}

module.exports = { CDPEventCapture, DIALOG_METHODS };
