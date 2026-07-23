Family Beacon — App Design Guide

Status: v0.1 (Draft, living document)

This is the working guide for building the Family Beacon clients (Android, iOS,
web). It owns the middle layer that no other document covers: product
functionality from the user's side, the user experience, the screen and flow
inventory, and the app-level design decisions we make as we build. It is meant to
be edited often — a place to iterate on *how the apps should work and feel*, not a
frozen spec.

It sits between, and defers to, the documents that are already normative:

- ARCHITECTURE.md — the system shape (Sund backend, clients, push, deployment).
- ETHICS.md / PRIVACY.md — normative policy. Where this guide and those disagree
  about what is allowed, they win.
- docs/FamilyBeacon-Protocol.md — the wire protocol (envelope, message types,
  consent state machine, ledger rule). Where this guide and the protocol disagree
  about what is on the wire, it wins.
- CLAUDE.md — the decision index and hard rules for contributors and agents.

When this guide records a *product/UX* decision that hardens, promote a one-line
pointer to CLAUDE.md's decision list so it is discoverable there too.

---

Design principles

These are derived from the ethics line and the protocol, restated as things a
screen must honor. They are the tie-breakers when a UX trade-off is unclear.

1. Consent is visible and legible, always. The person being shared can see, at
   any time and on their own device, exactly what they share, with whom, and can
   turn any of it off. Default is deny (a fresh pairing shares only a display name
   and the ability to receive an SOS). Sharing state is never hidden from the
   person it concerns — that is the predecessor's founding rule and it governs
   every screen.

2. No covert capability, ever. There is no hidden mode, no silent background
   share, no admin surveillance view. If a capability exists, the device's own
   user can see it in the ledger and disable it. Anything that makes the app
   harder for its own user to see, disable or uninstall is wrong — raise it.

3. Honest about limits. The UI never implies a stronger promise than the system
   makes. SOS is best-effort and is not an emergency service (see SOS below);
   location can be stale; the server can be down. We surface these plainly rather
   than designing reassurance the system can't back.

4. Calm, not attention-seeking. This is a safety and coordination tool for
   families, not an engagement product. No streaks, no gamification, no "seen"
   pressure, no dark patterns nudging more sharing. The best session is a short
   one.

5. Transparency is a feature, not a settings-screen afterthought. The activity
   ledger and the consent overview are first-class surfaces, reachable in a tap or
   two, understandable by a child old enough to carry a phone.

6. Graceful degradation. Offline, server-down, and slow-wake states are normal,
   not errors. The UI shows staleness truthfully and never fabricates freshness
   (never interpolate a location; say "last seen 2 h ago").

7. Platform-native where it matters. Respect each platform's conventions for
   permissions, background location, and notifications rather than forcing one
   look. Parity of *capability and honesty*, not pixel-identical UI.

---

Product scope

What the apps do, framed as user-facing capability. Ordered roughly by build
priority; the authoritative feature list and its long-term items live in
ARCHITECTURE.md.

v1 (the safety core)

- See family on a map — live location of members who share it with you, with
  honest freshness (timestamp, staleness, battery if shared).
- Share my location — per person, on/off, with a clear indicator that I am
  currently sharing and to whom.
- Battery status — optional, threshold-based ("Emma's phone is low").
- Geofences (places) — define a place; get an arrival/departure notification when
  a member who shares that with you enters or leaves. Evaluated on the moving
  member's own device (protocol: geofence_event), never server-side.
- Contact me urgently — a directed nudge to one member that overrides their silent
  mode / low ringtone to get their attention ("call me back, now"). Carries no
  data, is an inbound *allow* they control, and is deliberately not SOS. See Two
  urgent channels below.
- SOS — an explicit broadcast alert to the whole family about the sender's own
  situation ("I need help / find me"), best-effort and consent-overriding for its
  own content. See SOS below; it carries hard UI requirements.
- Family & pairing — add a device by an in-person QR ceremony; see the full family
  device list; leave the family or remove a lost device (revocation).
- Activity ledger — a readable log of everything sent and received on this device.
- Consent overview — one place to see and change every grant.

Later (see ARCHITECTURE.md "Long-Term Features" and the protocol's "Future
versions")

- Secure family chat (text first; images depend on Sund blob storage, a future
  version).
- Member avatars, shared images, large/stored configs — all gated on the Sund
  blob module (a Sund Non-goal until Family Beacon forces it).
- Location history, web interface parity, Home Assistant integration, guest
  access, webhooks.

Explicitly not in scope: covert/stealth modes, employer/partner monitoring
framings, anything that reads a member's data without their visible consent.

---

Core flows

Sketches of the flows that most shape the app. Each will get a detailed screen
spec as we build; here we fix the intent and the non-negotiable moments.

Onboarding & first device
- Explain, in plain language, what the app is and — up front — what it is not (not
  an emergency service; best-effort). This honesty belongs in onboarding, not only
  at the SOS button.
- Create or connect to the family's server (the Sund address, pinned by
  fingerprint from a QR). The trust ceremony is physical co-presence.
- Or start in **Try mode** with no server (docs/FamilyBeacon-TryMode.md). The
  choice is presented once, plainly, with what Try mode gives up — not as a
  "quick start" that hides a downgrade. Three things must be on that screen and
  not one layer deeper: messages can be lost if a phone is off for a long time,
  removing a device is weaker than with your own server, and moving to a server
  later means re-pairing every device. If the family already has a server,
  Try mode is not offered.
- Set a display name. Default sharing is nothing but name + SOS receipt.

Pairing a new family member (adding a device)
- In-person QR ceremony (single-use, short-TTL invitation token). No silent
  membership; the new device appears in every member's device list.
- Immediately after pairing, the new member shares nothing until grants are made —
  the UI should make that state obvious, not look "broken."

Granting / revoking a share (consent)
- Consent is per feature, per person, directional (I grant you to see my X).
- Granting and revoking are both one clear action, and both are ledgered.
- Revocation is immediate and cannot be blocked, delayed, or hidden by the
  observer. The UI must never present a peer as still-sharing after they revoked.

Live location
- Show freshness honestly: timestamp, "updated N min ago," stale after a
  threshold. Never interpolate position between updates.
- A persistent, non-dismissable indicator while I am actively sharing my location
  (also a platform requirement for background location on both OSes).

Geofence / arrival-departure
- Creating a place is a shared config item (owned by its creator; protocol
  config_update ownership model).
- The crossing is detected on the moving device; the notification is the product.
  Make it clear whose arrival/departure and at which place.

Urgent contact / SOS (safety-critical — see the two dedicated sections)

Leaving / revoking
- A member can leave the family, and a lost/stolen device can be revoked by the
  family; the UI states plainly that after this the departed device can no longer
  read the family's traffic.

---

Two urgent channels — "Contact me" and SOS

The app has two ways to break through, and they answer different questions.
Conflating them is the likeliest design mistake in this product: one is about the
*recipient's attention*, the other is about the *sender's situation*.

| | Contact me urgently | SOS |
|---|---|---|
| Answers | "I need **you** — get back to me now" | "Something is wrong with **me**" |
| Direction | directed at one named member (occasionally a few, chosen) | broadcast to the whole family |
| Subject | the recipient's availability | the sender's own state |
| Consent | inbound *allow*, per person, revocable | mandatory to receive, cannot be switched off |
| Carries | who is asking + an optional short reason. No location. | last-known location, overriding sharing grants |
| On the recipient's device | breaks through silent / low ringer to get attention | full alert, sticky, stays up until stood down |
| The ask | "answer me / call me back" | "know this, and act" |
| Stand-down | implicit: they respond, done | explicit sos_clear, broadcast to everyone |
| Expected frequency | mundane, several times a month | rare, ideally never |

Why both must exist as separate things: the common case is not an emergency at
all — the phone is in a bag, on silent, on a low ringtone, in a meeting, and I
need that one person *now*. If the only override in the app is SOS, that case
gets sent as SOS, and a family quickly learns to discount SOS. An alarm channel
that cries wolf is worse than no alarm channel. Giving the everyday interruption
its own channel is precisely what keeps SOS meaning what it says.

Rules that follow:

- **Different affordance, different place.** "Contact me" is addressed to a
  person, so it lives on the member (member detail / member row action). SOS is
  about me, so it lives at the app level (and on the widget/lock surface). Never
  adjacent, never the same gesture, and distinct in sound, color, wording and
  notification style. A user under stress must not be able to confuse them.
- **No auto-escalation, either way.** An unanswered "contact me" never turns
  itself into an SOS, and an SOS is never presented as a nudge that got serious.
  Escalation is a deliberate human act (the app may *offer* SOS after a
  repeatedly unanswered nudge, but only as a plain, clearly-labelled choice).
- **No implied data.** "Contact me" carries no location and requests none. If
  what I actually want is "where are you", that is the on-demand location pull —
  a separate allow, named as such in the UI, and ledgered as a location request.
- **Naming.** User-facing: "Contact me" / "Urgent" and "SOS" (sv: "Kontakta mig"
  / "SOS-larm"). Drop "panic button" from product language — it survives only as
  historical wording in ARCHITECTURE.md's feature list.

---

Urgent contact — the attention override

This is the only feature where I ask something of another person's *device*
rather than of their *data*. It discloses nothing, so the data-consent axis
barely applies; what it needs instead is an interruption budget and full
visibility.

- **Inbound allow, per person, revocable** (the member matrix). Unlike SOS
  reception, it is *not* mandatory: a named person being able to override the
  silence of my phone is exactly the asymmetric power the ethical line exists to
  bound — think of the coercive-partner case, not the parent-teen case.
- **Default deny**, like every other grant, but the pairing flow should offer it
  as one of a small set of suggested *mutual* grants, so a family enables it
  deliberately and symmetrically rather than one side acquiring it quietly.
- **Interruption budget, enforced at my device.** A cap on how often one member
  may override my ringer (order of a few per hour, with backoff on repeats).
  Past the cap the nudge still arrives — as an ordinary notification, without the
  override. This is the anti-harassment control; without it the feature is a
  nagging weapon in the relationships ETHICS.md is written about.
- **Never anonymous, always ledgered.** Sender's name and the reason string are
  shown on the alert and recorded in both devices' ledgers, sent and received.
- **Honest suppression.** If the override was suppressed (budget spent, quiet
  hours, member paused), the sender is told it was delivered without the
  override rather than being left to believe a phone was ignored.
- **Close the loop fast.** The recipient gets one-tap responses — "Calling you",
  "On my way", "Can't talk now" — and the sender sees delivered / seen / the
  reply. The product is the callback, not the alert.
- **Optional short reason**, a few words, length-capped ("call mum", "outside
  school"). It is a courtesy and it makes the override accountable.
- **Same honesty about reach as SOS.** Best-effort: the server can be down, the
  phone off, the OS may refuse the override. Never present break-through as
  guaranteed.

Platform reality (it constrains the promise, so it is stated here):

- Android — a dedicated high-importance notification channel that bypasses DND.
  Channel-level settings are visible and editable in system settings, which fits
  the transparency rule: the recipient can see and tune the override the app
  claims.
- iOS — time-sensitive notifications are reachable; true Critical Alerts (which
  ignore silent/Focus) need an Apple entitlement that SOS may plausibly justify
  and an everyday nudge probably does not. The app must not claim a tier it
  cannot deliver, and the iOS copy must say what it actually does.
- Both ride the same payload-free wake ping; the override lives in how the client
  presents the drained message, not in the push.

Scope: decided (July 2026) — urgent contact ships **in the v1 safety core**, not
with the v0.2 companions. It is small, it is the highest-frequency urgent action
in the product, and it reuses SOS's priority/wake machinery; shipping SOS without
it also invites exactly the misuse this section exists to prevent, since users
with no directed channel will reach for the broadcast one. The wire type
(`attention`) is specified in FamilyBeacon-Protocol.md → Message types — v1.

---

SOS — the broadcast alarm, and its hard UI requirements

SOS is the one flow where getting the UX honest matters most. These are
requirements, not suggestions (normative source: ETHICS.md → Safety limitations;
protocol sos type; CLAUDE.md decision #4).

- SOS is a *broadcast about the sender* — "I am in trouble, here is where I am",
  to everyone. The directed "I need you specifically" case is urgent contact
  above and must never be routed through SOS.

- The UI must state, where SOS is armed/triggered and in onboarding, that Family
  Beacon does not call emergency services and cannot guarantee delivery. No
  softening this to feel more reassuring than the system is.
- SOS overrides sharing for its own content (sends last-known location even if
  location sharing is off). This exception is disclosed at the button, not buried.
- Show delivery/acknowledgement state truthfully: "sending," "delivered to N
  devices," "seen by …" as receipts arrive — and, crucially, an honest
  unacknowledged state. Never imply "help is coming."
- Sending should be deliberate enough to avoid pocket-triggers but fast enough
  under stress (design target, resolve during build — e.g. press-and-hold vs.
  confirm).
- Standing down (sos_clear) is easy and clearly propagates to everyone.
- Open dependency: what the app promises when the server is unreachable (CLAUDE.md
  decision #4) — a degraded path may exist, but the UI must not promise more than
  best-effort regardless.

---

Cross-cutting UI requirements

The ethical line, made concrete on every screen:

- Activity ledger reachable in a tap or two; no message type is exempt from it
  (including SOS, consent changes, and unknown/ignored messages).
- A live "what am I sharing right now, and with whom" surface, always accessible.
- Sharing-active indicators that are visible and truthful, especially for
  background location.
- Every feature disableable; the app uninstallable; neither ever obstructed by the
  design.
- Staleness shown, never hidden or faked.
- Transparency works the same on a child's device — no covert mode to enable
  (PRIVACY.md → Children).

---

Glanceable UI — the family-state widget

The proposed primary surface after install and setup. For most users, most of the
time, the app should be a home-screen widget they glance at and don't open: a
single at-a-glance representation of "is the family OK right now?", with the full
app one tap away for detail and configuration. This is the "calm, not
attention-seeking" principle (4) made literal — the best session is not opening the
app at all.

Concept: a colored state indicator (a circle, or a small set of widgets at
different info densities) summarizing family status. Green everything's well,
yellow a soft problem, red a real one, with a severe/critical tier above that.
Tapping launches the app, ideally deep-linked to whatever caused a non-green
state.

State model (proposed — the colors carry weight, so they must be honest)

- OK (green) — every member I am granted to see has reported recently and shows no
  problem. Green means actively confirmed-recently, never merely "no bad news."
- Unknown / stale (neutral, e.g. grey) — I cannot currently confirm state. Two
  distinct causes, both of which must read as not-green:
    - a specific member's heartbeat has aged past the "fresh" threshold, or
    - the viewer is blind: my own device is offline or the family server is
      unreachable, so I know nothing about anyone right now.
  Conflating either with green would be the fake-freshness the ethics line forbids
  (principle 3, 6). The widget must be able to say "can't tell."
- Attention (yellow) — a soft, non-urgent problem: low battery, heartbeat missing
  for a while (approaching stale), a geofence condition worth noticing.
- Problem (red) — a hard problem: a member offline beyond threshold, or similar.
- Severe (red, emphasized) — a critical condition or an active SOS. See the
  animation caveat below: this tier is carried primarily by notifications, with the
  widget reflecting it on its next refresh, not by the widget alarming on its own.

Honesty and consent constraints (non-negotiable)

- No false green. See the state model — an unknown state is its own state, distinct
  from OK. A safety indicator that shows green while it actually has no data is
  precisely the dishonesty the app forbids.
- Consent-scoped aggregation. The widget summarizes only data the viewer has
  already been granted. If I lack a member's battery grant, their low battery
  cannot color my widget. The aggregate is honestly "of what I'm allowed to see."
- Not color-only. Status must not rely on color alone (accessibility requirement,
  and colorblind safety): pair each state with a distinct shape or symbol inside
  the indicator (e.g. check / dash / exclamation / cross) and a text label in the
  larger widgets and in the app.

Signal-to-state mapping — first-cut proposal

This operationalizes the state model above; it is the concrete proposal for open
decisions 3 and 9. Every threshold is a default to calibrate, not a constant — see
Calibration.

Signals the widget can read

- Liveness (heartbeat) — a consent-gated presence feature: a member declares an
  expected heartbeat interval and their observers judge silence against it. "Heard
  from within the interval" is satisfied by any message (an active location stream
  is already a heartbeat); an explicit lightweight presence ping fires only when
  the device is otherwise silent, so the traffic cost is near zero for active
  sharers. Independent of movement — a stationary phone stays green because the
  ping keeps arriving. Presence is a per-observer consent grant like any other:
  unselect a member and they receive the revoke and show "not shared." (This
  replaces an earlier idea of reading Sund's account-level last_seen; a
  consent-gated feature is honest per-observer, which last_seen cannot be — Sund
  exposes it to the whole account.)
- Location freshness — age of the member's latest location update. Requires a
  location grant. A location fix is a full heartbeat: for a member sharing live
  location on an interval, location age drives liveness exactly as a presence beat
  does, so such a member needs no separate presence grant. (When location is not
  shared, presence carries liveness; when neither is, the member is "not shared.")
- Battery — level_pct + charging, sent by the producer on threshold crossings.
  Requires a battery grant; the crossing thresholds are the producer's own config
  (below).
- Viewer sync health — when my own device last completed a successful server sync.
  Drives the viewer-blind (grey) override.
- Active SOS — an sos received from a member and not yet stood down (sos_clear).
  Sticky until cleared.

Producer-declared configuration (the config the widget interprets)

The thresholds that turn a signal into a color are owned and broadcast by the
producer, not guessed by the observer. An observer cannot honestly judge silence
without knowing the expected cadence — 45 minutes quiet is fine for a phone that
checks in every 30 minutes and alarming for one that checks in every 5. So:

- Heartbeat interval — each producer declares one expected interval, seeded by a
  role-based default (e.g. a child's device tighter than an adult's) and
  user-overridable. It rides in the presence heartbeat itself (the interval_s
  field), so every beat is self-describing; observers judge freshness against the
  most recent value and fall back to the role default until a beat arrives. See
  FamilyBeacon-Protocol.md → Presence heartbeat.
- Battery thresholds — the producer's own config for when a crossing is emitted
  (e.g. notify at ≤ 15%). These stay producer-local: the observer receives the
  resulting crossing event, not the policy. Broadcasting the numeric threshold to
  observers is optional polish (to label "Dad set low = 20%"), deferred.

Scope, deliberately (this is where the design stops short of overkill):

- Selection is per-observer (a managed member list, default all selected;
  unselecting a member sends them the revoke → they show "not shared"). This is
  exactly the existing consent state machine — no new mechanism.
- Parameters are per-producer, not per-observer. One heartbeat interval, one
  battery-threshold set, broadcast to whoever is selected. Per-observer parameter
  matrices (Emma sees a 5-min interval, Dad a 30-min one) are explicitly out of
  scope: the interval is a property of the device's behavior, not of the
  relationship.

Mechanically this rides mostly existing protocol pieces — consent_update for
selection; battery thresholds stay producer-local (events, not policy, on the
wire) — plus the presence heartbeat message type, which carries its own interval_s.
Now specified for v0.2 in the protocol doc (Presence heartbeat), gated on test
vectors like every type.

Per-member state (evaluate top-down; first match wins)

Thresholds are expressed in the producer's declared heartbeat interval I (with a
small grace), so they self-adjust to each device's cadence rather than assuming a
global constant.

| Condition                                                      | Member state |
|----------------------------------------------------------------|--------------|
| Active SOS from this member (until sos_clear)                  | Severe       |
| Silent for more than ~3× I (device offline)                    | Red          |
| Battery ≤ 5% and not charging                                  | Red          |
| Silent for ~1–3× I (missed a heartbeat or two)                 | Yellow       |
| Battery ≤ 15% and not charging                                 | Yellow       |
| Location granted and location age > 30 min (soft staleness)    | Yellow       |
| Heard from within I (+ grace), battery ok, no SOS              | OK (green)   |
| Member shares nothing with me (name + SOS receipt only)        | Not shared   |

"Not shared" is a muted, neutral state, shown distinctly and excluded from raising
the family aggregate: a member who has granted me nothing is a consent fact, not a
problem, and must never be colored as an alarm — doing so would pressure sharing
(a dark pattern, principle 4). Because presence is now a consent-gated feature, a
member who unselects me for heartbeat reads as fully "not shared" — there is no
residual account-level liveness leaking around the grant. Paused (from the "pause
1h" control) is a sibling benign state: a temporary, explicit "not shared until
~HH:MM" that likewise never raises the aggregate — distinct from offline/red, which
it must never be mistaken for. See Feature & member controls.

Family aggregate (what the single circle shows)

- Any member Severe, or any active SOS → Severe (red, emphasized; carried by
  notifications — see Platform reality).
- Else, viewer is blind (my last successful sync > 15 min ago, or no network) →
  Unknown (grey). I cannot vouch for green, so I do not claim it. A locally-held
  unresolved SOS still shows Severe — it is sticky.
- Else → the worst per-member state among members who share with me
  (Red > Yellow > OK). "Not shared" members do not raise it.
- All sharing members OK → OK (green).

Calibration (why these are defaults, not constants)

- Thresholds should be tunable and probably differ by context: a child's phone
  offline for 20 minutes may warrant attention sooner than an adult's; a family in
  poor coverage needs looser windows to avoid false alarms.
- Expected-offline / quiet hours: a phone off overnight on a charger should not
  blare red. Consider quiet-hours windows and/or treating known-charging as benign
  so the widget rests while the family sleeps — but carefully: quiet hours must
  never hide a real problem, and an SOS always overrides them.
- Alarm fatigue is the main failure mode. Too-tight thresholds train users to
  ignore the widget, defeating a safety tool. Calibrate toward "quiet unless it
  matters," with SOS and true offline as the signals that must never be missed.

Widget tiers (a set to choose from, mapped to platform size families)

- Minimal — the single state indicator only (smallest widget). "Is everyone OK?"
- Medium — the state indicator plus a per-member row/dot list with each member's
  own state.
- Rich — member list with status detail and/or a small map snippet (large widget).

Interaction

- Tap opens the app; a non-green widget should deep-link to the cause (the member
  or place responsible), not just the home screen.
- The widget is passive and ambient. It is a glance, not an alarm — actual alerts
  (SOS, a member dropping offline) also fire notifications so they reach the user
  when they are not looking at the home screen.

Platform reality (constrains the design, so stated here)

- Widgets cannot free-run animation. iOS WidgetKit is timeline-based with a limited
  refresh budget and no arbitrary animation; Android App Widgets update via
  rate-limited RemoteViews. "Red blinking" as a continuous widget animation is not
  reliably available and would fight battery. Severe/SOS urgency is therefore
  carried by the notification system (which can be high-priority, sounding,
  full-screen), and the widget shows the state when it next updates.
- Refresh cadence is budgeted by the OS, not chosen freely. The widget's own
  "freshness" is itself subject to staleness — reinforcing why an unknown/stale
  state is required rather than optional.

This surface raises the stakes on defining the freshness thresholds (open decision
3): the widget makes "fresh vs. stale vs. offline" directly visible, so those
thresholds become user-facing, not internal.

---

Feature & member controls

Where the widget is the ambient glance, this is the depth a tap leads to: two
surfaces, a per-feature control and a per-member sharing matrix. Together they are
the "consent overview" named in Product scope, and the ledger's forward-looking
twin — the ledger says what happened, these say what is set.

Share vs. allow — two directions of consent

A distinction the controls make explicit, because the features fall into two
kinds:

- Share (outbound) — I push my data to a member: heartbeat/presence, live location
  on a producer-set interval (see Live location below), safe-zone enter/exit events,
  and battery-level events. The toggle means "do I emit this to them."
- Allow (inbound) — I permit a member to reach or pull from me: send me an "urgently
  contact me" nudge that overrides my ringer, or request my most-current location on
  demand (a pull layered on the live-location share, not a separate feature). The
  toggle means "may they ask." A request I have not allowed never reaches me as an
  interruption (enforced at my device, like all consent).
- Mandatory (inbound, not toggleable) — receiving a family member's SOS, because it
  reports *their* situation rather than demanding something of me. This cannot be
  switched off; it is the one thing a fresh pairing already permits (ETHICS.md).
  Shown in the matrix as present and locked, with a one-line why. The contrast with
  the revocable urgent-contact allow above is deliberate — see Two urgent channels.

Feature map (per member, from my point of view):

| Feature                          | Direction     | Wire type (status)              |
|----------------------------------|---------------|---------------------------------|
| Heartbeat / presence             | share         | presence (v0.2)                 |
| Live location (interval + pull)  | share + allow | location (v1) + location_request (v0.2) |
| Safe zones (enter/exit)          | share         | geofence_event (v1)             |
| Battery level                    | share         | battery (v1)                    |
| Contact me urgently (directed)   | allow         | attention (v1)                  |
| SOS broadcast (receive)          | mandatory     | sos (v1), always on             |

Per-feature controls

For each feature the owning user has, mirroring the old SMS Android app's
per-feature screens:

- Enable / disable — a global on/off for the feature on my device, independent of
  who I share it with. Disabling stops the capability entirely (nothing emitted,
  no requests honored).
- Pause 1h — a one-tap temporary suspend that auto-resumes. The safety-first
  affordance: "I want an hour of privacy" without hunting through settings. Must be
  honest — see Pause and the state model below.
- Config — the feature's settings (heartbeat interval, battery thresholds, safe-zone
  definitions, location accuracy/cadence, etc.). Several of these screens port
  fairly directly from family-beacon-android.

The two axes compose: a feature can be globally enabled but shared with only some
members (the matrix), and can be paused across the board (the pause control) while
its per-member grants stay intact and resume with it.

The member matrix

- A full list of family members, one row each, with a column per feature; each cell
  is the share/allow toggle for that (feature, member) pair. This is exactly the
  protocol's per-(feature, observer) consent set, made visible and editable in one
  place.
- Group the columns by direction — "I share with them" and "I allow them to" — so a
  mixed-direction row does not read ambiguously. The SOS column shows locked-on.
- This matrix is my outbound/allow grants — what I emit or permit. It is distinct
  from the home/widget view, which shows what I receive from others. Keeping "what I
  share" and "what I see" as separate surfaces avoids the classic confusion of a
  single screen that conflates both directions.
- Default deny holds: a newly paired member's row is all-off except the locked SOS
  cell.

Live location

Live location was impossible in the SMS predecessor; the client/server architecture
makes it a real option, and it is modeled on the heartbeat rather than as a separate
request/response feature:

- Interval share — a producer sharing live location streams its position on a
  producer-set interval (a maximum gap, sent sooner on significant movement), the
  same shape as presence. Because a location fix is itself proof of liveness, an
  active location share is a heartbeat: a member sharing live location need not also
  share presence separately, and their location freshness feeds the widget's
  liveness directly (see the note in Signals). The interval is per-producer config,
  role-defaulted, like the heartbeat interval.
- On-demand pull — layered on the same grant: an observer can request the
  most-current fix (e.g. "where is Emma right now"). It is a convenience on top of
  the stream, not a separate feature — but the pull is a discrete, visible act and
  is ledgered as such on both sides (who asked, when), because asking is more
  pointed than passively receiving the stream.
- A lower "on-demand only" tier — allow requests without continuously streaming — is
  a possible privacy-minimizing setting; whether to offer it is a sub-decision.

Retention — last-known, not a trail

Received live location is retained as the member's last-known position only; the
app deliberately does not accumulate it into a movement history. Building a trail of
where a family member has been is the surveillance artifact the whole project exists
to avoid, and the safety use case ("where are they now, can I reach them") needs
only the current fix plus discrete safe-zone events — not a track log. Therefore:

- Others' locations: keep the latest fix, overwrite on update; no per-fix trail.
  Any opt-in "history of a member" would have to be exactly that — opt-in, both
  sides aware, off by default — like receipts; the default builds nothing.
- Safe-zone enter/exit stay as discrete, consented, individually meaningful events
  (that is the "was at school at 3pm" signal, bounded and legible — not a trail).
- My own location history is a separate choice (it is my own data); a user may keep
  their own trail locally if they want it, independent of the above.
- Ledger: consistent with the telemetry-aggregation rule — live location shows as
  active sharing with a last-update time, never a per-fix log.

This resolves ARCHITECTURE.md's former "Location history (under consideration)" as
no-trail-by-default, and is reflected in PRIVACY.md (Data and where it lives; Data
retention and deletion) and ARCHITECTURE.md (Database; Long-Term Features).

Pause and the state model

Pausing a share must not masquerade as a problem. If I pause my heartbeat or
location, my observers' widgets must show a benign paused state — a temporary,
explicit "not shared (until ~HH:MM)" — never offline/red, which would fire false
alarms across the family. That requires the pause to be communicated to affected
observers (a temporary consent revoke, ideally carrying the resume time), not just
a silent local stop. Resume restores the prior grants automatically. This adds a
benign Paused variant to the widget's per-member states, alongside Not shared.

Protocol implications (flagged, to specify next like presence)

- Live location on-demand pull needs a location_request/response pair: a
  location_request from the asker and the existing location message as the reply,
  gated by the location grant, ledgered as a discrete event on both sides (who
  asked, when). The interval-share half reuses the existing location type with a
  producer-declared max-gap interval, mirroring presence.
- Contact me urgently (allow) — done: specified as the v1 attention type
  (FamilyBeacon-Protocol.md), gated by its allow grant and rate-limited at the
  recipient. Not "SOS but weaker" — see Two urgent channels.
- Pause likely wants an explicit form on consent_update (a revoke carrying an
  "until" / auto-resume hint) so observers can render Paused rather than guessing.

None of these change the server (all ride Sund's blind queues); they are new
beacon-protocol types and are tracked as open decisions below.

---

Platform strategy

Parity of capability and honesty across Android, iOS, and web; native where the
platform demands it.

- Android — fullest capability. Background/foreground location, geofences, and
  self-hostable push via UnifiedPush/ntfy. Port selectively from
  family-beacon-android (GeofenceHelper, LocationFgService, consent flow,
  AuthHelper biometric, the Room event log, UI screens) — never the SMS layer.
- iOS — same product, structural push limits. Wake-ups transit APNS via a
  vendor-operated gateway (wake timing only). Location/geofence wake works without
  push at the source, but SOS latency without a push is unbounded — the SOS UX
  must account for this honestly. iOS push provider is not built yet (Sund
  Status).
- Web — likely a lighter companion (viewing, config, ledger, family management)
  before a full parity client; background location and reliable wake are limited
  in a browser. Scope to be decided.

Shared client logic is split into reusable libraries (sund-client generic,
beacon-protocol FB-specific); the implementation-strategy decision (Kotlin
Multiplatform vs. Rust core vs. per-platform native) is open — see the protocol
doc's open items and CLAUDE.md decision #6. This guide is about the product/UX and
stays above that choice.

---

Visual & content design

Placeholders to fill as the design system forms — recorded here so decisions land
in one place rather than being re-litigated per screen.

- Design system / tokens: to be defined (color, type, spacing, components). When
  we build any chart or data display, follow the shared dataviz guidance.
- Tone of voice: calm, plain, honest. Short sentences. No alarmism, no marketing
  gloss, no false reassurance. A child should understand the key screens.
- Localization: Swedish + English at parity, string files kept in sync (carried
  over from the predecessor's convention). Design for text expansion.
- Accessibility: target WCAG-level contrast, dynamic type, screen-reader labels,
  and non-color-only status (staleness, sharing-on, SOS state must not rely on
  color alone). Treat as a requirement, not a polish pass.
- Iconography and map styling: to be decided.

---

Open design decisions (app-level)

Tracked here the way CLAUDE.md tracks architecture decisions. Add, resolve, and
date them as we iterate.

1. SOS trigger interaction — press-and-hold vs. explicit confirm vs. both, and
   the pocket-trigger vs. speed trade-off. Open.
2. Web client scope — companion (view/config/ledger) first, or full parity. Open.
3. Location freshness thresholds and cadence defaults — what "stale" means in the
   UI, and default update cadence/significant-change policy (a client policy the
   protocol leaves to the app). Open.
4. Receipts UX — whether "delivered" receipts power a staleness/last-seen UI for
   routine location, mirroring protocol open item #3. Open.
5. Notification taxonomy — channels/categories, quiet handling, and how SOS and
   urgent contact each escalate above normal notifications on each platform. Open,
   and now two-tiered: they must be unmistakably different alerts, never one style
   at two volumes (see Two urgent channels).
6. Map provider / offline maps — which map, and offline behavior. Open.
7. Onboarding depth — how much of the honesty (not-an-emergency-service,
   best-effort, consent model) to front-load vs. surface in context. Open.
8. Widget as primary surface — is the family-state widget the default post-setup
   experience for most users (leaning yes)? Confirm and design accordingly. Open.
9. State-model details — exact mapping of signals (battery, heartbeat age, offline,
   SOS) to yellow/red/severe, and the neutral unknown/stale treatment; couples
   tightly to freshness thresholds (decision 3). Proposed — a first-cut table
   exists (see Signal-to-state mapping); needs review and threshold calibration.
   Shape decided: heartbeat is a consent-gated presence feature with a
   producer-declared, role-defaulted interval; selection is per-observer,
   parameters are per-producer (not a per-observer matrix); battery sends crossing
   events, thresholds stay producer-local. The presence type (carrying interval_s)
   is now specified for v0.2 — see FamilyBeacon-Protocol.md → Presence heartbeat.
   (The earlier presence-suppression sub-question is resolved: consent-gating
   presence makes it suppressible per member, with no last_seen leak.)
10. Widget set — how many widgets and which info densities/sizes to ship first
    (minimal / medium / rich), and deep-link targets per state. Open.
11. Location model — Decided (leaning): live location is an interval share modeled
    on the heartbeat (a location fix is a heartbeat), plus an on-demand pull layered
    on the same grant; retention is last-known-only, no movement trail built by
    default (see Live location). Remaining sub-questions: whether to offer an
    "on-demand only" tier (allow requests without streaming), and whether any opt-in
    history exists at all. No-trail decision confirmed and propagated to
    ARCHITECTURE.md (Database; Long-Term Features) and PRIVACY.md.
12. Allow-features protocol types — location_request (request/response, gated by the
    location grant) is still to be specified like presence was: open. The "contact
    me urgently" half is Decided (July 2026): specified as the v1 attention type,
    separate in kind from SOS (see Two urgent channels; CLAUDE.md decision #7).
    Remaining sub-questions are values, not shape — the interruption-budget numbers
    (how many overrides per hour, backoff curve) and the iOS notification tier the
    app can honestly claim.
13. Pause semantics — the "pause 1h" affordance must be communicated so observers
    render a benign Paused state, not offline/red; likely an "until"-carrying form
    of consent_update. Confirm mechanism and the widget's Paused state. Open.
14. Member matrix layout — column grouping by direction (share vs. allow), how the
    locked SOS column reads, and keeping "what I share" separate from "what I see."
    Open.

---

Relationship to other documents

- ARCHITECTURE.md — system shape and the authoritative feature list.
- ETHICS.md / PRIVACY.md — normative policy; win on questions of what is allowed.
- docs/FamilyBeacon-Protocol.md — the wire protocol; wins on what is on the
  wire. Its consent state machine and ledger rule are the enforcement layer under
  this guide's consent and transparency UX.
- ../sund/docs/Sund-Status.md — what the backend actually provides today
  (constrains iOS push, media, and availability promises).
- CLAUDE.md — decision index; promote hardened product/UX decisions here as
  one-liners.
