# Desktop notifications

Passless uses desktop notifications for local user interaction during FIDO2 ceremonies. Notification actions depend on the desktop notification daemon because the Freedesktop interface does not require every daemon to render actions as visible buttons.

## Dunst

Dunst supports notification actions, but normally exposes them through its own interaction model instead of inline `Accept` / `Deny` buttons.

For **CTAP user presence (UP)**, Passless sends a single default action on Dunst. Invoke the action on the Passless notification to confirm presence; Dunst uses middle-click for the default action by default, or you can use your configured `do_action` binding. Closing or dismissing the notification refuses the request.

For **user verification (UV)** and ordinary yes/no prompts, Passless keeps explicit actions instead of treating notification activation as approval. If Dunst does not render those actions visibly, use its action/context mechanism (for example `dunstctl context`) to choose the intended action.

This distinction is intentional: UP is an explicit presence/consent gesture, while UV has stronger verification semantics and should not be weakened by daemon-specific notification activation behavior.

## notify-osd

notify-osd (Ubuntu) does not advertise the `actions` capability, but it shows a notification with actions as a dialog with one button per action. Agent escalation prompts (`request` rules) work through that dialog: click **Allow always** or **Deny** (**Register once** or **Deny** on a registration prompt). `passless doctor --agents` reports notify-osd as OK with a note that it uses fallback dialogs.

notify-osd cannot close the dialog on Passless's behalf. When an escalation is withdrawn (the page aborted, the request timed out) its dialog may stay on screen; clicking it then does nothing. Every prompt has its own action keys, so an old dialog never answers a newer prompt.

Only a mouse click on **Allow always**, **Register once** or **Deny** answers a prompt. A keypress that lands on the dialog (Enter or space on the focused button, Escape, the window's close button, **Cancel**, or notify-osd's own **OK**) closes it and is treated as a dismissal: the request is denied, and the denial puts it in the escalation cooldown. A keypress never approves. The dialog takes focus when it opens, so Enter typed in another window at that moment can dismiss it.

## Agent registration prompt

A `register = "request"` rule (on an exact RP or on the `*` rule, see
[Rules](agents/rules.md#registration)) raises a prompt that is built not to be mistaken for a sign-in.
The summary is `Passless: CREATE A NEW PASSKEY? (not a sign-in)`. The actions are **Register once** and
**Deny**, with the keys `register_once:<nonce>` and `deny:<nonce>` (a fresh 128-bit nonce per prompt, as
for sign-in prompts). Approval is one registration, not "always", hence the label. The body is seven
lines at most, all derived by the daemon, never from the page or the agent:

```text
Action: create a new passkey and register it at this site
Site: example.org (NOT on your list; matched by the * rule)
Origin: https://example.org
Stored in: YOUR passkey store (same-user profile "coding"), which already holds 1 passkey for this site
Approving allows this one registration, then lets the agent sign in here without asking.
Requested by: a page now, principal user alice
```

`Site:` says `(your rule for this site)` for an exact rule and `(NOT on your list; matched by the * rule)`
for the wildcard. `Stored in:` says `YOUR passkey store` for a same-user profile and `the agent's own
store (isolated profile "name")` for an isolated one. The count says `already holds N passkeys for this
site`, `already holds 1 passkey for this site` or `holds no passkey for this site yet`; it comes from the
store's file names, never by decrypting anything, and is left out when a backend cannot count that way.
It is shown to you only and never reaches the agent or the page.

A decision that does not belong to the prompt counts as a deny: `Register once` can only approve a
registration prompt and `Allow always` only a sign-in prompt. The minimum review delay applies to both.

## Prompts the agent asked for in advance

When an agent asks before it navigates ([Asking in advance](agents/rules.md#asking-in-advance)), the
prompt is the same one with no page behind it. The sign-in prompt's body gains one line, so it is seven
lines in all, and its origin line reads `none yet`:

```text
Profile: coding (same-user)
Principal user: alice
Action: sign in with a passkey
Site: example.org (any page under this site)
Origin: none yet
Requested by: the agent in advance (no page is waiting)
"Allow always" is saved permanently.
```

A registration prompt keeps its six lines, with `Origin: none yet` and `Requested by: the agent in
advance (no page is waiting), principal user alice`. The buttons, keys and nonces do not change. Nothing
the agent wrote is shown: the `--note` of `passless agent request-access` goes to the audit log only.

## Supported notification servers

Agent `request` rules (escalation prompts) need a server that can show two distinct actions, **Allow
always** (**Register once** on a registration prompt) and **Deny**, and report which one was chosen. `passless doctor --agents` (the
`notification_bus` check) asks the server on the user's session bus for its name, version and
capabilities and applies the rule below. Without a usable server a `request` is denied at once and
audited; `allow` and `deny` rules never need one.

| Server | Escalation prompts | Why |
|---|---|---|
| dunst | Supported | Advertises `actions`. Actions are chosen through its action/context mechanism (see [Dunst](#dunst)). |
| mako, any version that is not `0.0.0` | Supported if it advertises `actions` | Passes the capability gate. |
| mako reporting version `0.0.0` | **Rejected** | Known to collapse distinct actions into one default action. |
| notify-osd 1.0 (Ubuntu) | Supported, through its fallback dialog | No `actions` capability, but a dialog with one button per action, which keeps the keys distinct ([notify-osd](#notify-osd)). Another notify-osd version is not assumed to behave the same. |
| GNOME Shell, KDE Plasma | Supported if the shell advertises `actions` | Passes the capability gate; not exercised by the project's tests. |
| quickshell (reporting an empty version) | **Rejected** | Known to collapse distinct actions into one default action. |
| Any other server | Supported if it advertises `actions`, otherwise rejected | `the notification server does not support actions`. |

The gate is `server_support` in `cmd/passless/src/agent/escalation_prompt.rs`. A rejected server is not
a bug in the prompt: install a supported one (dunst is the simplest standalone choice) and
`passless doctor --agents` will show `notification_bus` passing.

An agent that runs as your Unix user can drive your notification server and approve its own prompt:
see [Containment](agents/containment.md#same-user-and-different-user).
