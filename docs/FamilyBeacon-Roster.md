Family Beacon — Family roster

Status: v0.1 (Draft)

The layer named but not specified in `FamilyBeacon-Protocol.md` → Layering and
`FamilyBeacon-TryMode.md` → Where the seam goes: **membership, introductions and
revocation policy**, held as explicit client-side state above the transport port.

It exists as its own layer for one reason. Sund has a management plane — device
registry, key bundles, invitations, server-enforced revocation — and ntfy has no
analogue for any of it. Rather than widening the transport port until both
backends fit (which would design Sund mode down to ntfy's level), membership
becomes client-side logic that both modes run, and **Sund mode implements it more
strongly by additionally using its management plane** (CLAUDE.md decision #8).

There is a second reason, discovered in writing this down, and it turns out to be
the more important one: **the server's device list cannot be the authority on who
is in the family.** Sund's threat model includes an abusive host, and an abusive
host can add a row to the `devices` table. If a client admitted peers on the
strength of `GET /v1/devices`, the host could inject a device that every family
member would then pair with — defeating the E2EE stance not by breaking crypto but
by being introduced as a legitimate peer. The roster closes that hole: admission
requires a signed vouch from an existing member, carried end-to-end. The device
list is used for revocation and for locating key material, never for admission.

---

Where it sits

    Family Beacon apps        UI, notifications, policy, SOS escalation
    ─────────────────────────────────────────────────────────────────
    beacon-protocol           envelope codec, message types, consent, ledger
    ─────────────────────────────────────────────────────────────────
    family roster             THIS DOCUMENT — membership state machine,
                              introductions, removal, reconciliation
    ─────────────────────────────────────────────────────────────────
    transport port            send / subscribe / ack / channel lifecycle
    ─────────────────────────────────────────────────────────────────
    sund-client  │  ntfy-client

A note on the layering diagram, which reads as if the roster sits *below*
beacon-protocol and therefore cannot use its envelope. Split the two senses
apart:

- The roster's **wire messages are ordinary beacon-protocol types** (specified
  below, added to that document's type registry). They are versioned, encrypted,
  ledgered and consent-free exactly like every other type.
- The roster's **state** is what beacon-protocol depends on: the envelope's
  `sender` field is only meaningful because the roster says which device ids are
  family members and which identity key each one holds. That dependency is what
  the diagram is drawing.

So the layer boundary is one of state and policy, not of encoding. Nothing here
requires a second codec.

---

The model — device is the principal, member is presentation

**Decision (v0.1): the consent principal is a device, not a person.** A family is
a set of devices. Every grant, channel, ledger entry and revocation names a
device.

Members exist, but only as a *grouping for display*: a person may label several
of their devices as belonging to one member ("Dad's phone", "Dad's iPad" → Dad),
and the UI may show them as one row with the freshest signal winning. Underneath,
grants remain per-device.

Why this way round, given that the design guide's member matrix is drawn per
person:

- It is what the layers below already are. Sund's principal is a device with an
  Ed25519 identity key; a pair channel is device-to-device; `envelope.sender` is
  a device id. A person-level principal would need its own key and a
  device→person binding to prove — new cryptographic machinery for a
  presentation problem.
- It is the ethically precise version. A grant to a *person* silently extends to
  hardware you have never seen, including a device they add next month. A grant
  to a *device* is a grant to a thing that can be held up and pointed at. Given
  the anti-stalkerware line, the precise reading is the correct one — the shared
  family tablet in the hall is exactly the device a grant should not
  automatically reach.
- It keeps "no silent membership" honest. A new device is a membership event even
  when it belongs to someone already in the family.

The UI cost is real and is paid deliberately: granting to a person who has two
devices is two grants. The app may offer "share with all of Dad's devices" as a
convenience, but it **expands into per-device grants**, each separately shown,
separately ledgered and separately revocable. It never becomes a single grant
that a future device inherits.

Consequence for grouping: member grouping is local, unsigned, advisory metadata.
A device asserts its own `member_group` label in `member_info`; receivers may use
it to group rows and may override it locally. Nothing security-relevant reads it.

**Decided (July 2026): grouping is labelling only — there is no verification that
two devices belong to the same person, and none is wanted.** Verifying it would
need a person-level identity key, which is the very machinery the device-as-
principal decision avoids, and it would buy nothing: no grant, no channel and no
removal consults the group. A mislabelled group is a cosmetic error, visible to
everyone in the family, and it is corrected the way any label is. Clients must
therefore never present grouping as an assurance — "Dad's phone and Dad's iPad"
is how the rows are sorted, not a claim the app has checked.

Family size

**Bounded at 20 devices** (July 2026), as a build-time constant, not a
configuration key. It sizes the two things that grow: full-mesh pairing at
N·(N−1) channels (380 at the cap) and `roster_sync` at O(N) per sync. Twenty is
comfortably above any real family and comfortably below where either becomes a
design problem, so the constant exists to fail honestly rather than to be tuned.

Enforcement is at admission: a vouch that would exceed the cap is refused, with a
plain message on both the introducer's and the joiner's screen. It is never
enforced by silently dropping traffic or degrading sync — a family that hits the
cap must be told it has, not discover it as flakiness. Tombstoned devices do not
count toward the cap; only `active` records do.

Roles

Roles ("parent", "child", "adult") exist as **labels that seed defaults** — the
role-based default heartbeat intervals the design guide's open decision 3 and 9
refer to. Normative, and it is the whole of the roster's position on roles:

**A role never confers authority over another device.** There is no in-app admin.
A role may not grant the power to read, configure, silence or unshare on someone
else's behalf, and a device must never present a different truth to its own user
because of a role another device assigned it. A parent configuring a child's
sharing happens by handing the child the phone, not over the wire. This mirrors
ETHICS.md's server-side rule: the admin role is an operator role, not a
surveillance role — the roster's version is that there is no admin role at all.

---

Roster state

Each device holds a local roster: a set of **device records** and a set of
**removal records (tombstones)**, plus an epoch counter.

    device record
        device_id        transport-layer id (Sund device id; in Try mode the
                         id minted at join)
        identity_pk      Ed25519 public key — the thing actually being vouched
        display_name     self-asserted, changeable via member_info
        member_group     self-asserted grouping label (advisory, see above)
        role             self-asserted label seeding defaults (advisory)
        joined_at        RFC3339 UTC
        introduced_by    device_id of the voucher (the founding device vouches
                         for itself)
        state            active | removed

    removal record (tombstone)
        subject          device_id being removed
        reason           left | removed | lost
        removed_at       RFC3339 UTC
        removed_by       device_id of the signer
        epoch            the epoch this removal establishes

    epoch                integer, starts at 0, incremented by every removal

`identity_pk` is the security-bearing field; everything else is a label.
`display_name`, `member_group` and `role` are self-asserted by the device they
describe and are never authority for anything — a device that renames itself
"Mum's phone" gains nothing.

Tombstones are permanent within the family's life and are never garbage
collected. A roster that forgets a removal will re-admit the removed device on
the next reconciliation, which is precisely the failure a lost-phone removal must
not have.

---

Wire types (added to beacon-protocol's registry)

Three new types. All ride existing per-pair channels under existing session keys,
all are ledgered, and none is consent-gated — membership is not a shareable
feature, it is the precondition for having features. Each is a v1 type: the
roster is not deferrable to v0.2, because nothing works before it.

    roster_introduce
        subject      { device_id, identity_pk, display_name, member_group,
                       role, joined_at }
        epoch        the introducer's epoch at time of vouching
        vouch        Ed25519 signature by the *introducer's* identity key over
                     the canonical encoding of subject + epoch
        A vouch says: "I authenticated this device in person, and I am putting my
        name on it." It is the only path into a roster.

    roster_remove
        subject      device_id
        reason       left | removed | lost
        removed_at, epoch
        sig          Ed25519 signature by the remover's identity key over the
                     canonical encoding of subject + reason + removed_at + epoch
        A removal is a tombstone and is irreversible for that device id.
        Re-admission is a fresh join, with a fresh device id (see Re-admission).

    roster_sync
        epoch        sender's current epoch
        devices      [ { device_id, identity_pk, state } ], sorted by device_id
        digest       SHA-256 over the canonical encoding of the above
        Sent on reconnect, on wake, and periodically. Carries the whole roster
        because a family roster is small (tens of entries at most); there is no
        delta protocol and none is wanted.

`member_info` (already a v1 type) continues to carry `display_name`,
`member_group`, `role` and `proto_v` changes for an already-admitted device. It
is not an admission path: a `member_info` from a device with no roster record is
ledgered as unknown-sender and dropped, exactly like a message from a stranger.

Canonical encoding for all three signatures is the same canonical-JSON discipline
the protocol's test vectors already mandate, and the vectors must cover it — a
signature scheme with two encodings is a signature scheme with a forgery.

---

Admission — the introduction protocol

The founding device
    Creates the family. It self-vouches: a device record with
    `introduced_by = self`, epoch 0. Its identity key is the family's first root
    of trust. In Sund mode this is Walkthrough 1
    (`../../sund/docs/Sund-ImplementationGuide.md`); in Try mode it is the device
    that generates `family_secret`.

Joining device J, invited by existing member M
    1. The QR ceremony runs as the transport specifies — Sund's invitation token
       (Walkthrough 2) or Try mode's join secret and short-authentication-string
       comparison. **Physical co-presence is the authentication**, in both modes;
       this layer adds no ceremony of its own and weakens neither.
    2. M and J now share an authenticated channel. M sends J its current roster
       (all device records and all tombstones) plus M's own vouch for J.
    3. M broadcasts `roster_introduce` for J over its existing pair channels to
       every other member.
    4. Each existing member P verifies the vouch against M's identity key — which
       P already holds, because M is in P's roster — and admits J at
       **default-deny consent** (ETHICS.md: a fresh pairing shares nothing but
       `member_info` and the ability to receive an SOS).
    5. P establishes a pair channel with J: in Sund mode by fetching J's key
       bundle and running the asynchronous pairing; in Try mode by publishing to
       J's derived inbox. P verifies that the key material it retrieves matches
       the `identity_pk` in the vouch, and aborts loudly if it does not.
    6. J does the reciprocal for each P in the roster M gave it.

One QR per joining device, as the design guide requires — the O(N²) pairwise
scanning the mesh shape suggests is avoided by vouching, not by trusting the
server.

Why channels are established automatically but consent is not

A newly admitted device gets pair channels with everyone without anyone
approving it a second time. That is deliberate and is not a consent hole: **the
channel is the pipe, consent is the valve, and the valve ships closed.** Nothing
flows over a fresh channel except `member_info` and a possible SOS — and SOS
reception is mandatory by ETHICS.md, so a family member who cannot be reached by
an SOS is a bug, not a privacy feature. Requiring N approvals to complete a join
would mean a child who joined the family this morning cannot raise an alarm this
afternoon because an aunt has not tapped Accept.

What this deliberately does *not* do is auto-grant anything. The design guide's
"a newly paired member's row is all-off except the locked SOS cell" is the
observable consequence.

Verifying a vouch

- The introducer must be `active` in the verifier's roster at verification time.
  A vouch from a removed device is rejected and ledgered.
- A vouch for a `device_id` that already has a tombstone is rejected and
  ledgered. This is the rule that stops a removed device being quietly
  reintroduced by a member who missed the removal.
- A vouch that arrives over a channel whose authenticated sender is not the
  introducer is rejected — the same `sender`-mismatch rule the envelope already
  states.
- Vouches are not transitive beyond one hop and need no chain: every member is in
  every other member's roster, so every vouch is verified directly. There is no
  web of trust to walk.

Churn budget — rate limiting membership events

The size cap bounds how many devices exist at once; it does nothing about
*churn*. A hostile member can introduce and remove devices indefinitely, and each
cycle costs every other member a round of channel setup, key-bundle fetches,
roster syncs, ledger entries and notifications — and costs them *quota*, which
Sund charges to the recipient (Sund-Status → Trust boundary). Tombstones do not
count toward the size cap, so the cap alone leaves this unbounded.

**Decided (July 2026): a per-introducer budget on membership events, enforced
locally by every verifier.**

    MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY = 5    (build-time constant)

Four things about this design are load-bearing, and three of them are not the
obvious choice:

1. **Enforced at the verifier, never at the introducer.** The introducer is the
   attacker; a budget it applies to itself is decoration. Each device evaluates
   every incoming vouch against its own local count of that introducer's recent
   activity. No coordination, no shared counter, and it therefore works
   identically in Try mode.

2. **The window is wall-clock, not epoch.** Per-epoch was the obvious unit and is
   exactly backwards: every removal bumps the epoch, so an introduce/remove
   attacker resets their own budget with each cycle — the attack would pay for
   its own allowance. The window is a rolling 24 hours, evaluated against the
   event's signed timestamp, clamped against future-dating for clock skew (the
   same clamp the presence spec applies to `sent`).

3. **The budget counts removals too, but never refuses one.** Both
   `roster_introduce` and `roster_remove` signed by a device consume its budget,
   because churn is the two of them in a loop and budgeting only admissions would
   miss half the cycle. But an over-budget *removal is still applied
   immediately* — it only counts. The asymmetry is the same one the whole
   document runs on: removal takes capability away and is fail-safe, admission
   grants capability and is fail-dangerous. A stolen-phone removal must never be
   delayed by a rate limiter, whatever else that device has been doing. Not
   counted at all: a device removing itself (leaving is not churn inflicted on
   the family) and the founder's self-vouch.

4. **Over budget means held for approval, not rejected.** An exceeded budget
   quarantines the vouch at the verifier: it is ledgered, surfaced with the
   count that triggered it ("Dad's phone has added or removed 6 devices today —
   admit Emma's tablet?"), and admitted only if the verifier's own user says so.
   A hard reject would make an honest family setting up six devices in an
   afternoon look broken, and would hand an attacker a way to *deny* admission by
   burning a victim's budget on their behalf — which quarantine does not, since
   the human can always approve.

Consequence for the SOS argument, stated because it is a real exception to the
"channels auto-establish, consent does not" rule above: a quarantined device is
not yet reachable by the members who quarantined it, so it cannot raise an SOS
to them until someone approves. That is the correct trade only because the budget
sits well above ordinary family behaviour — five membership events per device per
day is a setup-day number, not a Tuesday number — and because the joiner is never
fully isolated: the introducer's own channel exists from the QR ceremony
regardless. If the constant ever needs raising to keep honest families out of
quarantine, raise it; do not weaken the quarantine into an auto-admit.

---

Removal

Who may remove what — normative:

- **A device may always remove itself, and may always leave the family.** This is
  the roster-layer form of "the app can be disabled or uninstalled at any time"
  (ETHICS.md). No configuration, role or peer may block it.
- **Any active device may remove any other device.** There is no privileged
  remover.

The second rule looks permissive and is chosen against the abusive-member
scenario rather than in spite of it. Concentrating removal in an "admin" would
hand exactly the wrong person a lock: the member who controls the family would be
the only one who can end anyone's participation, including their own victim's
ability to eject a device the abuser controls. The failure mode of the permissive
rule is a family argument conducted by eviction — recoverable by re-pairing,
loud, and fully ledgered. The failure mode of the restrictive rule is a person
trapped in a family they cannot alter. We take the recoverable one.

Guardrails that make it survivable, and they are requirements not polish:

- Removing someone else's device is announced to the whole family (the tombstone
  is broadcast) and ledgered on every device, naming the remover.
- The removed device is told, when it is reachable. It must never simply
  discover it has gone quiet.
- The UI states the consequence before confirming, per mode: in Sund mode the
  removed device's keys and queues die; in Try mode the epoch bumps and members
  who are offline during the bump may need re-admission
  (`FamilyBeacon-TryMode.md` → Rotation and revocation).

Effects of a removal, in both modes:

1. Epoch increments.
2. Every remaining device drops its pair channels with the subject (`retire` on
   the transport port) and stops emitting to it immediately.
3. **All grants naming the subject are dropped locally**, in both directions.
   They are not suspended and they do not resurrect.
4. The tombstone is durable; the device record moves to `state = removed` and is
   kept, so the family's history stays readable in the ledger.

Sund mode additionally — this is the "stronger implementation" the layering
promises:

5. `POST /v1/devices/{id}/revoke`. The server kills the identity key, clears the
   push endpoint and retires every queue the device owns, atomically. The removed
   device's signed requests fail from that moment; it is not merely un-addressed,
   it is locked out.

Try mode has step 5's client-side half only, and says so.

Re-admission

A removed device that returns re-joins through the full ceremony and receives a
**fresh device id and a fresh identity key**; the tombstone on the old id stands
forever. Consent starts at default-deny — grants never resurrect. Local history
(ledger, geofences, last-known positions) is device-local and unaffected either
way; the family does not restore it and does not delete it.

---

Reconciliation

Roster state converges by merge, not by an authority.

Merge rule, applied on every `roster_sync` and on every `roster_introduce` /
`roster_remove`:

1. **Tombstones win over device records, always and regardless of epoch.** A
   device seen as removed by any peer is removed locally. Removal is
   monotonic; there is no un-remove.
2. Device records merge by union. A record for a device you already have updates
   only its advisory labels, and only when the update is authenticated as coming
   from that device itself.
3. Epoch is `max(local, received)`. It orders removals for Try mode's topic
   derivation; it is not a vector clock and does not arbitrate content.
4. A `roster_sync` whose digest matches locally is a no-op — the common case, and
   the reason sync can run often and cheaply.
5. A `roster_sync` that reveals a device you have never seen is **not** an
   admission. It is an anomaly: ledger it, show it, and wait for a vouch. Sync
   spreads knowledge of removals quickly and knowledge of additions only as
   confirmation of a vouch you can verify.

Rule 5 is the counterpart of the admission rule, and rule 1 is what makes a
lost-phone removal reliable in a family whose devices are rarely all online at
once.

Split families — mutual eviction

Two devices can remove each other, concurrently or in ignorance of each other.
Both tombstones are valid and tombstones are monotonic, so the roster partitions:
each side holds a removal for a device that holds a removal for it, and different
members may have seen only one of the two.

**Decided (July 2026): surface it, do not resolve it.** There is no principled
winner — the two removals are signed by equally authorized devices, and any
automatic tie-break (earlier timestamp, lower device id, larger surviving
partition) would let a device manufacture the outcome by choosing its clock, its
id, or its moment. Worse, a tie-break would resolve *silently* an event that is
almost always a human conflict, which is the failure mode ETHICS.md forbids
everywhere else: presenting a state that is not the true one.

So the state machine keeps both tombstones and the app says what happened:

- Detection is local and needs no coordination — a device holds a tombstone for
  D while D holds one for it, which any device learns from its own roster plus
  the next `roster_sync`.
- The UI states the split plainly, names both parties, and shows **who can still
  see whom** from this device's point of view. The user's actual question is
  "am I still connected to my daughter", and that is answerable locally even
  though the family-wide picture is not.
- Both removals are already ledgered as ordinary removal events; the split gets
  its own ledger entry naming both sides.
- The exit is the ordinary one: whoever is meant to still be in the family
  re-joins by the join ceremony, with a fresh device id (see Re-admission). No
  special merge path exists, and none should be added.

This is a rare, human-caused state. The design goal is that a person reading the
screen understands what happened to their family, not that the software quietly
picks a side.

Sund mode: reconciling against the server device list

The server's list is consulted every wake and before any new pairing (Sund
requires this anyway). It is authoritative for **removal and for key material
location** — never for admission. Four cases, all of which must be handled and
three of which are user-visible:

| Server says | Roster says | Action |
|---|---|---|
| revoked | active | Treat as removed. The server can only take away, and a host that lies in this direction merely denies service — which is visible. |
| listed | active | Normal. Use the device's bundle for pairing; verify the retrieved key material against the roster's `identity_pk`. |
| listed | unknown | **Do not admit.** Ledger and surface: a device exists on the server that no family member vouched for. This is the injected-device signal — it is the one place a dishonest host becomes visible to the family. |
| absent | active | The device was revoked server-side, or the list is being manipulated. Mark unreachable, surface it, do not tombstone on this evidence alone. |

The asymmetry is the point: a host that adds devices is detected, and a host that
removes them can deny service but cannot read anything. That is the strongest
statement available given that the host controls the list at all, and it is worth
stating in PRIVACY.md alongside the residual-metadata paragraph.

Try mode: reconciling without a server

There is no second opinion. `roster_sync` over the family topic is the whole
mechanism, and the epoch drives topic derivation
(`FamilyBeacon-TryMode.md` → Topics). This is the concrete shape of that
document's open item #1 for membership state specifically — the grant-state
digest it calls for is the same pattern applied to consent, and the two should
share an implementation.

---

Ledgering

No exemptions, per the protocol's ledger rule. Discrete, individually visible
entries — none of these is telemetry, and none may be aggregated away:

- a device joined, and who vouched for it
- a device was removed, by whom, and for which stated reason
- a vouch was rejected, and why (removed introducer, existing tombstone,
  sender mismatch, size cap reached)
- a vouch was held for approval over the churn budget, with the count that
  triggered it — and, separately, its later approval or denial and by whom
- a device appeared on the server that no one vouched for (Sund mode)
- an epoch bump, and in Try mode the members believed stranded by it
- the family split by mutual eviction, naming both sides
- a display name, member grouping or role label changed

The rule of thumb this follows: **if it changes who can reach you, it is a ledger
event with a sentence a person can read.** "Emma's phone was removed by Dad's
phone" is the standard; a row of ids is not.

---

Open items

1. ~~Eviction conflicts.~~ **Decided July 2026: surfaced at the UI, never
   auto-resolved.** See Reconciliation → Split families.
2. ~~Family size bound.~~ **Decided July 2026: 20 devices, a build-time
   constant, enforced at admission.** See The model → Family size.
3. ~~Vouch rate limiting.~~ **Decided July 2026: a per-introducer churn budget,
   enforced at the verifier, over-budget admissions held for approval.** See
   Admission → Churn budget. Note that the per-epoch form suggested here
   originally was wrong — removals bump the epoch, so the attack would have reset
   its own allowance.
4. ~~Member grouping across devices.~~ **Decided July 2026: labelling only, no
   verification.** See The model → Consequence for grouping.
5. **Founding-device special case.** The founder self-vouches, so a family's
   entire trust structure roots in one QR-less act. Whether a second device should
   co-sign the founding record before the family grows past two is worth deciding.

---

Relationship to other documents

- `FamilyBeacon-Protocol.md` → Layering names this layer; the three types above
  belong in its registry, and its test vectors must cover the vouch and removal
  signatures.
- `FamilyBeacon-TryMode.md` → Where the seam goes, Topics, Rotation and
  revocation — the weaker of the two implementations of everything here.
- `FamilyBeacon-DesignGuide.md` → Core flows (pairing, leaving/revoking), Feature
  & member controls — the UX over this state machine.
- `../ETHICS.md` — no silent membership, no covert capability, always able to
  leave; the roster is where those become mechanism.
- `../ARCHITECTURE.md` → Authentication — family membership as Sund account
  membership, refined here: the account bounds the family, the roster decides it.
- `../../sund/docs/Sund-Status.md` → Guarantees and residual metadata (Trust
  boundary) — the "consumers that cannot assume mutual trust enforce peer
  acceptance client-side" note that this document is the answer to.
- `../../sund/docs/Sund-ImplementationGuide.md` → Walkthroughs 1 and 2 — the
  transport-level ceremonies admission rides on.
