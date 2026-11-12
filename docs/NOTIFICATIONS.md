# Desktop notifications

Passless uses desktop notifications for local user interaction during FIDO2 ceremonies. Notification actions depend on the desktop notification daemon because the Freedesktop interface does not require every daemon to render actions as visible buttons.

## Dunst

Dunst supports notification actions, but normally exposes them through its own interaction model instead of inline `Accept` / `Deny` buttons.

For **CTAP user presence (UP)**, Passless sends a single default action on Dunst. Invoke the action on the Passless notification to confirm presence; Dunst uses middle-click for the default action by default, or you can use your configured `do_action` binding. Closing or dismissing the notification denies the request.

For **user verification (UV)** and ordinary yes/no prompts, Passless keeps explicit actions instead of treating notification activation as approval. If Dunst does not render those actions visibly, use its action/context mechanism (for example `dunstctl context`) to choose the intended action.

This distinction is intentional: UP is an explicit presence/consent gesture, while UV has stronger verification semantics and should not be weakened by daemon-specific notification activation behavior.

## notify-osd

notify-osd (Ubuntu) does not advertise the `actions` capability, but it shows a notification with actions as a dialog with one button per action. Agent escalation prompts (`request` rules) work through that dialog: click **Allow always** or **Deny**. `passless doctor --agents` reports notify-osd as OK with a note that it uses fallback dialogs.

notify-osd cannot close the dialog on Passless's behalf. When an escalation is withdrawn (the page aborted, the request timed out) its dialog may stay on screen; clicking it then does nothing. Every prompt has its own action keys, so an old dialog never answers a newer prompt.

## Supported notification servers

Agent `request` rules (escalation prompts) need a server that can show two distinct actions, **Allow
always** and **Deny**, and report which one was chosen. `passless doctor --agents` (the
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
