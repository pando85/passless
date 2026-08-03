#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');

const FORBIDDEN_CDP_METHODS = ['WebAuthn.enable', 'WebAuthn.addVirtualAuthenticator', 'WebAuthn.addCredential'];
const FORBIDDEN_FILE_PATTERNS = [/\.pass\//, /\.password-store\//, /vault/i, /\.gpg$/];
const EXPECTED_SELECTOR = 'a.signin-passkey';
const LOGIN_PATH = '/user/login';

function selfCheck() {
  const source = fs.readFileSync(__filename, 'utf8');
  const lines = source.split('\n');
  const violations = [];
  for (const method of FORBIDDEN_CDP_METHODS) {
    let foundAsCall = false;
    for (const line of lines) {
      if (line.includes('FORBIDDEN_CDP_METHODS')) continue;
      if (line.includes('selfCheck')) continue;
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
      if (line.includes("send(") && line.includes("'" + method + "'")) {
        foundAsCall = true;
      }
      if (line.includes("send(") && line.includes('"' + method + '"')) {
        foundAsCall = true;
      }
    }
    if (foundAsCall) violations.push(method);
  }
  for (const pattern of FORBIDDEN_FILE_PATTERNS) {
    for (const line of lines) {
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
      if (line.includes('FORBIDDEN_FILE_PATTERNS')) continue;
      if (line.includes('selfCheck')) continue;
      if (pattern.test(line)) {
        violations.push('file_pattern:' + pattern);
      }
    }
  }
  return { pass: violations.length === 0, violations: violations };
}

class GateCDriver {
  constructor(cdpPort, rpUrl, evidenceDir) {
    this.cdpPort = cdpPort;
    this.rpUrl = rpUrl;
    this.evidenceDir = evidenceDir;
    this.ws = null;
    this.messageId = 0;
    this.pending = new Map();
    this.connected = false;
    this.calledMethods = [];
  }

  async connect() {
    const targetsResp = await fetch('http://127.0.0.1:' + this.cdpPort + '/json/list');
    if (!targetsResp.ok) throw new Error('Failed to list targets: ' + targetsResp.status);
    const targets = await targetsResp.json();
    const page = targets.find(function(t) { return t.type === 'page'; });
    if (!page) throw new Error('No page target found');

    const self = this;
    return new Promise(function(resolve, reject) {
      const timeout = setTimeout(function() { reject(new Error('CDP connect timeout')); }, 10000);
      try {
        self.ws = new WebSocket(page.webSocketDebuggerUrl);
        self.ws.onopen = function() { clearTimeout(timeout); self.connected = true; resolve(); };
        self.ws.onerror = function(e) { clearTimeout(timeout); reject(new Error('WS error')); };
        self.ws.onmessage = function(event) {
          try {
            const msg = JSON.parse(event.data);
            if (msg.method) self.calledMethods.push(msg.method);
            if (msg.id !== undefined && self.pending.has(msg.id)) {
              const p = self.pending.get(msg.id);
              clearTimeout(p.timer);
              self.pending.delete(msg.id);
              if (msg.error) p.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
              else p.resolve(msg.result);
            }
          } catch (_) {}
        };
        self.ws.onclose = function() {
          self.connected = false;
          for (const [, p] of self.pending) { clearTimeout(p.timer); p.reject(new Error('CDP closed')); }
          self.pending.clear();
        };
      } catch (e) { clearTimeout(timeout); reject(e); }
    });
  }

  async send(method, params) {
    if (FORBIDDEN_CDP_METHODS.indexOf(method) !== -1) {
      throw new Error('FORBIDDEN: ' + method);
    }
    const id = ++this.messageId;
    const self = this;
    return new Promise(function(resolve, reject) {
      const timer = setTimeout(function() { self.pending.delete(id); reject(new Error('Timeout: ' + method)); }, 30000);
      self.pending.set(id, { resolve: resolve, reject: reject, timer: timer });
      self.ws.send(JSON.stringify({ id: id, method: method, params: params || {} }));
    });
  }

  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', { expression: expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error('JS: ' + (result.exceptionDetails.text || JSON.stringify(result.exceptionDetails)));
    return result.result;
  }

  async navigate(url) {
    return this.send('Page.navigate', { url: url });
  }

  async run() {
    const selfCheckResult = selfCheck();
    const result = {
      self_check: selfCheckResult.pass ? 'pass' : 'fail',
      self_check_violations: selfCheckResult.violations,
      navigation_ok: false,
      click_ok: false,
      url_origin: 'unknown',
      url_path: 'unknown',
      title_class: 'unknown',
      called_forbidden: false,
      duration_ms: 0
    };

    const startTime = Date.now();

    try {
      await this.connect();

      const loginUrl = this.rpUrl.replace(/\/$/, '') + LOGIN_PATH;
      await this.navigate(loginUrl);
      await new Promise(function(r) { setTimeout(r, 3000); });

      const navExpr = '(function(){return JSON.stringify({url:window.location.href,origin:window.location.origin,pathname:window.location.pathname,title:document.title})})()';
      const navResult = await this.evaluate(navExpr);

      const navData = JSON.parse(navResult.value || '{}');
      result.url_origin = navData.origin || 'unknown';
      result.url_path = navData.pathname || 'unknown';
      var rpOrigin;
      try { rpOrigin = new URL(this.rpUrl).origin; } catch (_) { rpOrigin = ''; }
      result.navigation_ok = (navData.origin === rpOrigin);

      var titleText = navData.title || '';
      result.title_class = titleText.length > 0
        ? (titleText.toLowerCase().indexOf('login') !== -1 ? 'login_page' :
           titleText.toLowerCase().indexOf('dashboard') !== -1 ? 'dashboard' :
           titleText.toLowerCase().indexOf('account') !== -1 ? 'account' : 'other')
        : 'empty';

      var clickExpr = '(async function(){try{var link=document.querySelector("' + EXPECTED_SELECTOR + '");' +
        'if(!link)return JSON.stringify({found:false,error:"selector_not_found"});' +
        'link.click();' +
        'await new Promise(function(r){setTimeout(r,5000)});' +
        'return JSON.stringify({found:true,after_origin:window.location.origin,after_pathname:window.location.pathname,after_title:document.title});' +
        '}catch(e){return JSON.stringify({found:false,error:e.message})}})()';
      const clickResult = await this.evaluate(clickExpr);

      const clickData = JSON.parse(clickResult.value || '{}');
      if (clickData.found) {
        var afterOrigin = clickData.after_origin || '';
        var afterPath = clickData.after_pathname || '';
        var afterTitle = clickData.after_title || '';
        var originMatches = (afterOrigin === rpOrigin);
        var authIndicator = (afterPath.indexOf('/login') === -1 && afterPath.indexOf('/user') !== -1) ||
            afterTitle.toLowerCase().indexOf('dashboard') !== -1 ||
            afterTitle.toLowerCase().indexOf('account') !== -1;
        if (originMatches && authIndicator) {
          result.click_ok = true;
        }
        result.url_origin = afterOrigin || result.url_origin;
        result.url_path = afterPath || result.url_path;
        result.title_class = afterTitle.length > 0
          ? (afterTitle.toLowerCase().indexOf('dashboard') !== -1 ? 'dashboard' :
             afterTitle.toLowerCase().indexOf('account') !== -1 ? 'account' :
             afterTitle.toLowerCase().indexOf('login') !== -1 ? 'login_page' : 'other')
          : result.title_class;
      }

      for (var i = 0; i < this.calledMethods.length; i++) {
        if (FORBIDDEN_CDP_METHODS.indexOf(this.calledMethods[i]) !== -1) {
          result.called_forbidden = true;
        }
      }
    } catch (err) {
      result.error = err.message;
    }

    result.duration_ms = Date.now() - startTime;

    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
    }

    return result;
  }
}

async function main() {
  const cdpPort = parseInt(process.env.AV_CDP_PORT || '9222', 10);
  const rpUrl = process.env.AV_REAL_RP_URL;
  if (!rpUrl) throw new Error('AV_REAL_RP_URL is required');
  const evidenceDir = process.env.AV_EVIDENCE_DIR || '/tmp';

  const driver = new GateCDriver(cdpPort, rpUrl, evidenceDir);
  const result = await driver.run();

  const sanitized = {
    self_check: result.self_check,
    self_check_violations: result.self_check_violations,
    navigation_ok: result.navigation_ok,
    click_ok: result.click_ok,
    url_origin: result.url_origin,
    url_path: result.url_path,
    title_class: result.title_class,
    called_forbidden: result.called_forbidden,
    duration_ms: result.duration_ms
  };

  if (result.error) sanitized.error_class = result.error.substring(0, 100);

  const outputFile = path.join(evidenceDir, 'gc-driver-output.json');
  try { fs.writeFileSync(outputFile, JSON.stringify(sanitized, null, 2) + '\n'); } catch (_) {}

  process.stdout.write(JSON.stringify(sanitized) + '\n');
  process.exit(result.called_forbidden ? 3 : (result.navigation_ok ? 0 : 1));
}

if (require.main === module) {
  main().catch(function(err) {
    process.stderr.write('Gate C driver error: ' + err.message + '\n');
    process.exit(2);
  });
}

module.exports = { GateCDriver: GateCDriver, selfCheck: selfCheck, FORBIDDEN_CDP_METHODS: FORBIDDEN_CDP_METHODS, EXPECTED_SELECTOR: EXPECTED_SELECTOR };
