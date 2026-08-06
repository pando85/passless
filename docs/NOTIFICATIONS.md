# Desktop notifications

Passless uses desktop notifications for local user interaction during FIDO2 ceremonies. Notification actions depend on the desktop notification daemon because the Freedesktop interface does not require every daemon to render actions as visible buttons.

## Dunst

Dunst supports notification actions, but normally exposes them through its own interaction model instead of inline `Accept` / `Deny` buttons.

For **CTAP user presence (UP)**, Passless sends a single default action on Dunst. Invoke the action on the Passless notification to confirm presence; Dunst uses middle-click for the default action by default, or you can use your configured `do_action` binding. Closing or dismissing the notification denies the request.

For **user verification (UV)** and ordinary yes/no prompts, Passless keeps explicit actions instead of treating notification activation as approval. If Dunst does not render those actions visibly, use its action/context mechanism (for example `dunstctl context`) to choose the intended action.

This distinction is intentional: UP is an explicit presence/consent gesture, while UV has stronger verification semantics and should not be weakened by daemon-specific notification activation behavior.
