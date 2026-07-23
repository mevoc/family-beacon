# Privacy Policy – Family Beacon

Family Beacon is designed with privacy as a core principle: your family's data
is end-to-end encrypted between your family's devices and coordinated by a
server your family runs itself. There is no vendor cloud holding your data.

This document is normative for the client/server Family Beacon and replaces
the predecessor's SMS-era policy for this product.

## Data and where it lives

- **Content** — locations, battery status, SOS alerts, geofence events,
  settings: end-to-end encrypted between family devices. Readable only on the
  devices of family members you have shared with. The server stores these
  messages briefly as ciphertext (until delivered or expired) and can never
  read them.
- **On your device** — other members' **last-known location only** (a new
  position overwrites the previous one; the app does not build a movement trail
  of anyone), your own location history if you opt to keep it (local-only, off
  by default), geofence definitions and their enter/exit events, the activity
  ledger, and your consent settings, in a local store on the device.
- **On your family's server** — the relay's minimal records: the family
  account, each device's public key and push endpoint, encrypted key bundles,
  queue records, and undelivered encrypted messages. No plaintext content,
  ever, and no stored record of which device sends to which.

## What the server operator can and cannot see

The server is a blind relay (`sund`; its threat model is the normative
reference). The family member hosting it:

- **Cannot** see message content, locations, or SOS details.
- **Cannot** look up who communicates with whom — the schema does not record
  it.
- **Can** see traffic timing and sizes, the list of devices, and which device
  owns which mailbox. In a small family, timing patterns can suggest who is
  active. Family Beacon does not claim resistance to this kind of traffic
  analysis, and you should not rely on it hiding *that* you communicated —
  only *what* you communicated.

## Data sharing within the family

- All sharing is opt-in, per feature and per person. A new family member
  receives nothing until you grant it — except your name, and any SOS you
  explicitly trigger.
- An explicit SOS includes your last known location even if location sharing
  is off. This is disclosed in the consent screen.
- Delivery/read receipts for routine updates are off by default and opt-in
  for both sides.
- Revoking a grant takes effect immediately on your device; nothing further
  leaves it for that feature.

## Third parties

- **No analytics, no ads, no trackers.**
- **Android:** none required. Push wake-ups go through your own family's
  UnifiedPush distributor (e.g. ntfy on the same server).
- **iOS:** wake-ups must transit Apple's push service (APNS) and a push
  gateway operated by the app vendor, because iOS permits no self-hosted
  alternative. These parties see your device's push token, the app's
  identity, and when your device is woken — never any content, and the
  wake-up signal itself carries nothing at all.
- **Try mode** (the serverless option, if your family uses it instead of
  running a server): your messages pass through an ntfy instance — a public
  one such as ntfy.sh unless your family runs its own. That operator
  **cannot** read anything: content stays end-to-end encrypted between your
  devices exactly as it is with your own server. What that operator **can**
  see is more than a Sund server sees: because each device receives on its own
  topic, the operator can observe which of your family members exchange
  messages with which, and when — a link your own server deliberately does not
  record. The operator also decides how long undelivered messages are kept, and
  makes your family no availability promise. The app tells you when you are in
  this mode, and your activity ledger records which transport each message
  used. See docs/FamilyBeacon-TryMode.md.

## User control

- Every feature can be disabled at any time.
- You can see everything the app has sent or received in its activity ledger.
- You can leave the family at any time (your device is removed and further
  traffic is unreadable to it); the app can be uninstalled at any time.
- A lost or stolen device can be revoked by the family; the family's
  subsequent traffic is unreadable to it.

## Data retention and deletion

- Undelivered messages on the server expire and are deleted unread after
  their time-to-live.
- Delivered messages are deleted from the server on acknowledgment.
- Revoking a device removes its server records and retires its mailboxes.
- No movement trails. The app keeps only the last-known position of the members
  who share with you, overwriting it on each update — it does not accumulate a
  history of where a family member has been. Your own location history is the
  one exception you control: off by default, kept locally only if you turn it on.
- Your local data is yours: stored on your device, deletable in the app.
- The server's entire state is one database file under the host's control —
  including its backups, which the host is responsible for protecting and
  pruning.

## Children

Family Beacon is intended for family use, typically including children.

- Parents or guardians are responsible for ensuring appropriate and
  transparent use on a child's device.
- Transparency tooling works on the child's device too: the child can see
  what is shared, with whom, in the same ledger and consent screens. There is
  no covert mode to enable.
- Age-appropriate honesty is the intent: a child old enough to carry a phone
  is old enough to be shown what it shares.

## Self-hosting and the GDPR

For purely personal or household use — a family running its own server for
itself — the GDPR's household exemption typically applies. Even so, the host
should act as if responsible: the server holds (encrypted) personal data of
family members, often minors. Keep the server updated, protect and prune
backups, and remove departed members' devices promptly.

If you host a server for people beyond your own household, you may take on
data controller responsibilities under the GDPR. This document is not legal
advice; know your situation before hosting for others. For a practical
orientation — the household-vs-others line, the obligations that attach, and an
operational checklist — see docs/FamilyBeacon-HostingGuide.md.

## Contact

If you have questions about privacy, please open an issue in the project
repository.
