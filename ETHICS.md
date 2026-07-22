# Ethical Use Policy – Family Beacon

Family Beacon is built to support safety and communication within families.
It is **not** intended for surveillance or control.

This document is normative for the client/server Family Beacon. It carries over
the predecessor's policy (`../family-beacon-android/ETHICS.md`) and extends it
for an architecture that now includes a server.

## What this app is for

- Emergency communication
- Family safety
- Situational awareness with consent

## What this app is NOT for

- Covert tracking
- Monitoring without the device user's knowledge
- Surveillance of partners, employees, or others
- Reading your family's data because you happen to run the server

## Design decisions

To prevent misuse, Family Beacon includes:

- Explicit consent per feature, per person: a fresh pairing shares nothing
  except your name and the ability to receive an SOS. Default is deny.
- Consent enforced at the source: data for a feature you have not granted
  never leaves your device. Enforcement is not the observer's UI politely
  hiding things — the data does not exist off-device.
- Revocation that cannot be blocked, delayed, or hidden by the other side.
- A visible activity ledger: every message sent or received is logged on the
  device, and every feature's sharing state is visible to the person being
  shared. There are no exempt message types.
- Joining a family is an explicit act (a QR ceremony, in person). Every device
  in the family is visible to every member. No silent membership.
- Device-lock protection for configuration changes.
- The app can be disabled or uninstalled at any time.

One stated exception: an **explicit SOS** sent by the device's own user
includes their last known location even if location sharing is not otherwise
granted. The person pressing the button is asking to be found. This exception
is disclosed in the consent UI, not buried here.

## Safety limitations — Family Beacon is not an emergency service

Family Beacon helps a family stay in touch and find each other. It does **not**
connect to emergency services and gives **no guarantee** that any message —
including an SOS — is delivered. Users and developers must treat it that way.

- **Not a 112 / 911 replacement.** The SOS button notifies your own family
  members through your family's own server. It does **not** contact the police,
  ambulance, fire service, an alarm-monitoring company, or any operator or
  authority. In a real emergency, call the official emergency number.
- **No delivery guarantee.** Delivery is best-effort. It depends on your
  family's self-hosted server being up and reachable, on network connectivity at
  both ends, and — especially on iOS — on push wake-up that carries no timing
  promise. A home server can be off or lose power; a phone can be offline or
  dead. An SOS can therefore be delayed indefinitely or never arrive, and the
  sender must not assume it was seen.
- **Say so in the UI.** These two facts are not fine print. The app must state —
  where a user arms or triggers SOS, and during onboarding — that Family Beacon
  does not call emergency services and cannot guarantee delivery. Softening or
  hiding this to make the feature feel more reassuring than it is would be
  dishonest, and is forbidden by the same rule that forbids overstating privacy.

## The server side

The family member who hosts the server holds a position the SMS predecessor
never created. Family Beacon's answer is structural, not policy:

- The server is a blind relay (`sund`). It stores encrypted payloads it cannot
  read and does not record who talks to whom. The host cannot read locations,
  messages, or SOS content — there is no admin view, no database query, no
  log level that reveals them.
- The admin role is an operator role: install, back up, upgrade, remove lost
  devices. It is not a surveillance role, and the software must never make it
  one.
- Honesty about the remainder: a host can still observe traffic timing, sizes
  and the device list, and in a small family such patterns can suggest who is
  active. We state this in PRIVACY.md rather than rounding it down to zero.

## Responsibility

By using this app, you agree that:

- You have the right to configure it on the device
- The device user is informed about its behavior
- If you host the server, you operate it for the family — not over them
- You will respect local laws and ethical norms

If these conditions cannot be met, **do not use this app**.

## Open source responsibility

As an open-source project, contributors are expected to:

- Respect the ethical goals of the project
- Avoid adding features that enable covert surveillance — client-side or
  server-side. A feature that requires the server to understand message
  content is rejected by design, not reviewed case by case.
- Favor transparency and user control over convenience

Any change that makes the app harder for its own user to see, disable, or
uninstall — or that gives the server operator covert insight into the family —
is a change in the wrong direction. Raise it, don't implement it.
