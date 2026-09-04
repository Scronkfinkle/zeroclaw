# CalDAV calendar

The `caldav` tool lets the agent read your calendar and, once you allow it,
create, update, and delete events. It speaks standard CalDAV (RFC 4791), so it
works with Fastmail, iCloud, Nextcloud, Radicale, Baikal, SOGo, and other
standards-compliant servers.

The tool is disabled by default, and even when enabled it starts read-only.

## Quick start (Fastmail)

Create an app password first. Fastmail's account password will not work for
CalDAV, and neither will iCloud's.

1. In Fastmail, go to Settings, then Privacy & Security, then App Passwords.
2. Create a new app password scoped to **Calendars (CalDAV)**.
3. Add the following to your `config.toml`:

```toml
[caldav]
enabled = true
base_url = "https://caldav.fastmail.com/dav/"
username = "you@fastmail.com"
password = "your-app-password"
```

The password is encrypted at rest the first time ZeroClaw writes the config.
You can also leave `password` empty and set the `CALDAV_PASSWORD` environment
variable instead.

Check that it works:

```bash
zeroclaw chat "what's on my calendar this week?"
```

## Enabling writes

Reading is enabled by default. Each write action has to be added explicitly:

```toml
[caldav]
allowed_actions = [
  "list_calendars", "list_events", "get_event",
  "create_event", "update_event", "delete_event",
]
```

Add only the actions you want. Listing `create_event` without `delete_event`,
for example, lets the agent book time but never remove anything.

The agent's own autonomy setting still applies on top of this. Write actions
count as `Act` operations, so a read-only or approval-gated profile blocks them
even when they appear in `allowed_actions`.

## Configuration reference

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Register the tool. |
| `base_url` | (required) | The server's DAV root, e.g. `https://caldav.fastmail.com/dav/`. |
| `username` | (required) | Usually your full email address. |
| `password` | (required) | App password. Encrypted at rest. Falls back to `CALDAV_PASSWORD`. |
| `default_calendar` | first found | Calendar used when a request does not name one. Accepts a display name or an href. |
| `allowed_actions` | the three read actions | Actions the agent may call. |
| `allow_private_hosts` | `false` | Permit a server on a private or loopback address. See below. |
| `timeout_secs` | `30` | Per-request timeout. |

## Self-hosted servers

`base_url` is dialled by the agent, so by default it must resolve to a public
address. A server on your own network is refused with an error naming the
setting to change:

```toml
[caldav]
base_url = "http://192.168.1.10:5232/"
allow_private_hosts = true
```

Turn this on only for a server you run. It relaxes the guard that otherwise
stops a calendar URL from being pointed at your local network.

## Repeating events

Repeating events are expanded by the **server**, so "what's on my calendar this
week" correctly lists a weekly standup once per occurrence rather than once in
total.

Editing them is a different matter. Because a repeating event is stored as a
single item plus a recurrence rule, changing or deleting it through CalDAV
changes or deletes **every** occurrence. The tool refuses to do that and tells
you so:

```
refusing to update event 'weekly-standup' because it repeats
(FREQ=WEEKLY;BYDAY=MO). Editing a repeating event here would change every
occurrence. Use your calendar app for recurring events.
```

Use your calendar application for those. One-off events have no such limit.

If your server does not support server-side expansion, the tool falls back to
reporting the raw recurrence rule and says so in its output rather than
under-reporting your schedule.

## Concurrency

Updates and deletes carry the event's `ETag` as a precondition. If the event
changed on the server since the agent read it, the write is refused rather than
overwriting that change, and the agent is told to re-read and retry. This is
what stops an agent from clobbering an edit you made on your phone a moment
earlier.

## What it does not do

- It does not send meeting invitations. Adding `attendees` records them on the
  event; it does not email anyone (no iTIP or scheduling support).
- It does not create, rename, or delete calendars.
- It does not manage tasks (`VTODO`) or free/busy queries.
- It does not edit repeating events, as described above.
