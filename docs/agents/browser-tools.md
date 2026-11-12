# Browser tools

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Passless starts and owns the browser: a managed Chromium with the interception extension, one per
principal session. Your tool attaches to it over CDP. Never start a second browser: a browser the
daemon did not start has no interception, and its WebAuthn calls go to whatever authenticator the
browser finds. The recipes below need the profile to set `browser_cdp_expose = "port"` (see
[Quick start](quick-start.md)); with the default `pipe` the browser has no endpoint and the agent
drives it through `passless agent browser-control` ([Pipe mode](#pipe-mode)).

The browser belongs to a principal session and closes when that session ends. A tool that runs
inside the session (started by `passless agent run --profile P -- <command>`) can ask for the
browser with `passless agent browser`. The MCP adapters start a session of their own.

| Tool | How | Status |
|---|---|---|
| Playwright MCP (primary) | `passless agent mcp playwright` | Tested: E2E-34 and E2E-35 (`--isolated`) |
| chrome-devtools-mcp | `passless agent mcp chrome-devtools` | Scenario E2E-36, local-full matrix only |
| Playwright library | `connectOverCDP(PASSLESS_CDP_URL)` | Scenario E2E-37 |
| browser-use | `cdp_url` | Optional local scenario E2E-38 (runs only when browser-use is installed) |
| agent-browser | `--cdp` | Optional local scenario E2E-39 (runs only when agent-browser is installed) |
| Stagehand | `cdpUrl` | Documented only, not tested |

"Scenario" means an end-to-end test exists in `tests/agent-e2e`; a tool marked optional is skipped,
not failed, where it is not installed.

## Playwright MCP

```bash
passless agent mcp --print-config claude-code     # or opencode, cursor, vscode
```

The entry runs `passless agent mcp playwright --profile <name>`, which runs `npx --yes
@playwright/mcp --cdp-endpoint <endpoint>` as its own child and starts a principal session for the
profile, which answers Playwright MCP's discovery requests. The browser starts on the first
discovery request from Playwright MCP, not when the server starts.

The server survives a daemon restart or upgrade: the process your MCP client started keeps the stdio
connection and the Playwright MCP server. While the daemon is down, browser tool calls fail at once
with `passless daemon unavailable, retrying ...`; the first browser tool call after it is back starts
a new principal session, with the new daemon's policy and grants, and a new browser. The pages of the
old browser are gone, as after any restart. A session that the running daemon ends (revoked, expired,
its grants revoked or its profile disabled) is not renewed: the server exits and the client must
restart it. This needs the session to run as your own Unix user; for a profile whose sessions run as
another user the server runs inside the session, as that user, and exits with the daemon.

- `--profile` may be left out when exactly one profile is configured.
- Pass options through to Playwright MCP after `--`. For contexts that Playwright creates over CDP
  use `--isolated`: `passless agent mcp playwright --profile coding -- --isolated`. The extension is
  allowed in incognito in the managed browser, so isolated contexts stay intercepted.
- Pin the package: `--package @playwright/mcp@<version>`. Without it `npx` takes whatever the
  registry serves. `--npx <absolute path>` names `npx`; by default it is the first `npx` on `PATH`,
  which must not be writable by group or others.
- `--url <URL>` opens a page once the extension is attached.
- The adapter hands the bootstrap bearer to Playwright MCP through an environment variable, never an
  argument.

`--print-config` prints an entry only. To pass `--isolated`, add `"--", "--isolated"` to its `args`.
The entry's `command` is the absolute path of the running `passless`; if passless cannot tell it, the
entry says `passless` and the MCP client must find it on its `PATH` (`cargo install` puts it in
`~/.cargo/bin`), or you put the absolute path there. The first call runs `npx --yes @playwright/mcp`,
so it needs Node and network. The managed browser is headless by default; for a visible one set the
profile's `browser_command` to the browser's absolute path with no arguments
([Containment](containment.md#supported-browsers)).

### Switching from a plain Playwright MCP

A plain `npx @playwright/mcp` entry starts a browser of its own: passkeys in it reach your human
authenticator, not the agent policy (`passless doctor --agents` warns about it). One command rewrites
such entries, and chrome-devtools-mcp entries, to the wrapper; the agent keeps the same tools.

```bash
passless agent mcp install --client opencode --user --profile coding          # dry run: prints a diff
passless agent mcp install --client opencode --user --profile coding --yes    # write, after a backup
```

- `--client opencode|claude-code`; `--user` (the default) or `--project <DIR>`. Files: opencode
  `$XDG_CONFIG_HOME/opencode/opencode.json` (`~/.config/opencode/opencode.json`) or
  `<DIR>/opencode.json`; Claude Code `$CLAUDE_CONFIG_DIR/.claude.json` (else `~/.claude.json`) or
  `<DIR>/.mcp.json`.
- Found: `@playwright/mcp` and `chrome-devtools-mcp` started with `npx`, `pnpm dlx`, `bunx`, `yarn dlx`
  or a local `playwright-mcp` binary. Each is rewritten in place; its other keys (`env`,
  `enabled`, `timeout`) stay, and so does the version pin (as `--package`).
- `--profile` is needed unless exactly one profile uses `browser_cdp_expose = "port"`. The profile
  must exist and use port mode: the adapters refuse pipe mode.
- The wrapper runs `npx`, so `pnpm dlx`, `bunx` and `yarn dlx` entries become the same package through
  `npx` (an absolute `npx` path is kept as `--npx`).
- Flags that suit an attached browser pass through after `--` (`--isolated`, `--viewport-size`,
  `--caps`, `--output-dir`, ...). Dropped, with a note each: `--browser`, `--executable-path`,
  `--user-data-dir`, `--cdp-endpoint`, `--cdp-header`, `--extension`, `--endpoint`, `--device`,
  `--mobile`, `--no-sandbox`, `--headless` and `--headed` (headed or headless comes from the Passless
  profile). For chrome-devtools-mcp the launch flags (`--browserUrl`, `--executablePath`,
  `--headless`, `--isolated`, ...) are dropped.
- The entries run the first `passless` on `PATH` (so a dev build can install entries for the packaged
  one), else the running executable; `--passless-path <ABS>` overrides. The command notes a differing
  choice, warns about a path inside a cargo `target/` directory, and refuses a `passless` without
  `agent mcp playwright`.
- `--yes` backs up to `<file>.passless-backup-<UTC timestamp>`, then replaces the file atomically with
  the same permissions. Running it again reports `already uses Passless`. Only the two values of each
  entry change; the rest of the file stays byte for byte.
- A file with comments or trailing commas (JSONC) is never rewritten: the command prints the entries
  to paste instead and refuses `--yes`.
- `--skill` installs or refreshes the bundled `passless-agent` skill for the client (a differing copy
  is backed up first).

Restart the client afterwards. `passless doctor --agents` should now report the entry as running
through Passless.

## chrome-devtools-mcp

```bash
passless agent mcp --print-config claude-code --server chrome-devtools
```

Runs `npx --yes chrome-devtools-mcp --browserUrl <endpoint>`. Unlike the Playwright adapter the
browser starts when the server starts: puppeteer asks for `<browserUrl>/json/version` and cannot send
the bootstrap's bearer header. The server exits when the browser's debugging port stops answering,
and the MCP client restarts it. Unlike the Playwright adapter it does not survive a daemon restart:
it is bound to the browser's own endpoint, which a new daemon replaces. A client that does not restart
MCP servers (opencode) needs a restart after the daemon's. The same `--package`, `--npx` and `--url`
options apply; extra arguments for `chrome-devtools-mcp` go after `--`.

## Playwright library with connectOverCDP

Inside a principal session, ask for the endpoint, then connect:

```bash
passless agent run --profile coding -- /bin/sh -c \
  'export "$(passless agent browser --env --wait)" && exec /usr/bin/node agent.js'
```

```javascript
const { chromium } = require('playwright-core');

const browser = await chromium.connectOverCDP(process.env.PASSLESS_CDP_URL);
const context = browser.contexts()[0];
const page = context.pages()[0] || await context.newPage();
await page.goto('https://github.com/login');
```

`passless agent browser` is idempotent: it starts the browser on the first call and prints the same
endpoint while it runs. `--env` prints `PASSLESS_CDP_URL=http://127.0.0.1:<port>`, `--json` prints an
envelope with the interception state, with no flag it prints the bare URL. `--wait` blocks until the
extension is attached and allowed in incognito; the endpoint is withheld until then, so a printed
endpoint is always an intercepted browser. `--headed` starts a visible browser, `--url` opens a page.
`agent run` takes an absolute command path.

Run from a plain shell, `agent browser` fails with a message that explains this: a browser started
there would close as soon as the command returned.

## browser-use, agent-browser and Stagehand

These tools take the same endpoint. Start them inside a principal session as above.

```python
# browser-use (0.7 or later)
from browser_use import Browser
browser = Browser(cdp_url=os.environ["PASSLESS_CDP_URL"])
```

```bash
# agent-browser
agent-browser --cdp "$PASSLESS_CDP_URL" open https://github.com/login
```

```javascript
// Stagehand (documented, untested): connect to the existing browser instead of launching one
const stagehand = new Stagehand({
  env: "LOCAL",
  localBrowserLaunchOptions: { cdpUrl: process.env.PASSLESS_CDP_URL },
});
```

The browser-use and agent-browser APIs change between releases; the scenarios in
`tests/agent-e2e/scenarios/e2e-38-39-optional-tools.test.js` show the calls the tests make. A tool
that launches its own Chromium instead of attaching defeats Passless and gets no passkeys.

## Pipe mode

With `browser_cdp_expose = "pipe"` (the default) the daemon keeps the browser's CDP pipes: there is no
endpoint, so Playwright, chrome-devtools-mcp, browser-use and the other tools above cannot attach, and
`passless agent mcp ...` refuses the profile. Inside a principal session `passless agent browser`
still starts the session's browser, waits for interception with `--wait`, and prints how to drive it
(`--json` prints `endpoint: null` and a `control_command`; `--env` fails, there is nothing to export).
The agent then sends each CDP command through the daemon:

```bash
passless agent run --profile coding -- /bin/sh -c '
  passless agent browser --wait --url https://github.com/login
  passless agent browser-control --request "{\"id\":1,\"method\":\"Target.getTargets\"}"'
```

Every command is audited and the daemon's filter keeps the agent away from the Passless extension (its
worker, `chrome-extension:` and `chrome:` URLs): see [Operations](operations.md#driving-a-pipe-mode-browser).
Ordinary page CDP works: navigate (`Page.navigate`), evaluate (`Runtime.evaluate`), and
the page's `navigator.credentials.get()` is signed on the agent path. A passkey login through
`browser-control` is exercised by E2E-52. Use `port` for the tools above, accepting that the agent
then holds an unmediated CDP connection ([Containment](containment.md#cdp-port-mode)).

## Limits

- CDP is full control of the browser session, including every authenticated site in it. Treat a tool
  that holds the endpoint as holding the session ([Containment](containment.md#cdp-port-mode)).
- Passkey autofill (conditional mediation) is unavailable: sites need an explicit sign-in button.
- Chrome rejects a passkey registration (`create()`) from a tab that is not in the foreground. Bring
  the page to the front (Playwright `page.bringToFront()`). If it was not, the daemon may have
  created the credential while the page got `NotAllowedError`; the audit shows it and
  `passless agent-admin credential delete` removes it.
