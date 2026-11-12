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
