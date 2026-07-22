Family Beacon — Hosting Guide (practical & legal)

Status: v0.1 (Draft)

For anyone who wants to run a Family Beacon server — for their own family, or for
other people. It covers the practical side of hosting and the obligations that come
with it, with an emphasis on the one distinction that changes almost everything:
whether you host only for your own household, or for others.

Not legal advice. This is a plain-language orientation written by the project, not
a lawyer. It leans on EU law (the GDPR) and Sweden, since that is the project's
home; other countries differ. If you host for others at any scale, or you are
unsure which side of the line you are on, get advice from someone qualified in your
jurisdiction. PRIVACY.md and ETHICS.md are the normative project documents; this
guide sits alongside them.

---

What the server actually holds

Start here, because it shapes everything below. Family Beacon's server (Sund) is a
blind relay: it stores end-to-end-encrypted ciphertext it cannot read, plus minimal
routing metadata. Concretely (see Sund's threat model and PRIVACY.md):

- It CANNOT see: locations, SOS content, messages, geofences, who talks to whom.
  There is no admin view, database query, or log level that reveals content.
- It DOES hold, as personal data: device public keys, push endpoints, queue
  records, undelivered ciphertext (briefly, until delivered or expired), and — in
  operation — connection timing, sizes, and IP addresses in any logs.

The second list matters legally: encrypted content and metadata are still "personal
data" under the GDPR even though you cannot read the content. The blindness reduces
your exposure and your risk enormously; it does not make you a non-processor of
personal data.

Why this helps you. The architecture does a lot of compliance work for you: strong
encryption (a security measure the law expects), data minimisation, no stored
relationship graph, short retention (messages are time-limited and deleted), and
per-device transparency and deletion built into the app. You inherit these; you
still own the operational and, if you host for others, the legal wrapper.

---

The line that changes everything

Hosting for your own household. Running the server for yourself and the people you
live with is, in EU terms, likely a "purely personal or household activity" — the
GDPR's household exemption (Art. 2(2)(c)). In practice this means few formal
obligations. You should still host responsibly (see the checklist), but you are not
running a data-processing operation for strangers.

Hosting for others — the moment it changes. As soon as the server serves people
beyond your own household (friends, extended family in other homes, another family,
a community), the household exemption stops protecting you, and you likely become a
data controller (or a processor, or a joint controller — the roles are genuinely
fuzzy for a blind relay). At that point the GDPR applies to you, and the
obligations in the next section attach. Charging money, hosting for the public, or
hosting at any real scale removes all doubt: you are a controller and should treat
it seriously.

If you are not sure whether you have crossed the line, assume you have and read on.

---

If you host for others — what you take on

None of this is exotic; it is the standard controller duty set, scaled to a small
operation. In plain terms:

- Have a reason (lawful basis). For a cooperating family, consent is the natural
  basis; make sure people actually agree, can withdraw, and are not children giving
  consent they cannot give (see Children).
- Tell people (transparency). Give the people you host a short, honest notice: what
  the server stores, what you as host can and cannot see (point them at PRIVACY.md —
  it is written for exactly this), how long data is kept, and how to reach you. Do
  not overstate the privacy: say plainly that you can see metadata and timing.
- Honour their rights. People can ask to access, correct, or delete their data, and
  to leave. The app already does most of this (the on-device ledger shows what was
  shared; revoking a device removes its server records and retires its mailboxes).
  Know how you would handle a request that the app does not cover.
- Keep it secure (Art. 32). Appropriate technical and organisational measures — the
  checklist below is your baseline. The E2E encryption is a big part of this, but it
  is not the whole of it.
- Handle a breach. If the server is compromised, assess what was exposed (with
  Family Beacon: ciphertext plus metadata, not readable content — which materially
  lowers the impact) and, if there is a risk to people, notify your supervisory
  authority within 72 hours and, if the risk is high, the people affected (Art.
  33/34). In Sweden the authority is IMY (Integritetsskyddsmyndigheten).
- Keep light records. Note what you process and why. Small operations have some
  relief from formal record-keeping, but a page of notes is cheap and sensible.
- Mind where the server lives. A box in your home in the EU is simplest. A VPS
  outside the EU/EEA can raise international-transfer questions (GDPR Chapter V);
  prefer EU hosting if you host for others.

---

Children

Family safety apps involve minors by design, so this is not a footnote.

- Children's personal data gets specific protection under the GDPR (Art. 8). The age
  at which a child can consent to online services themselves varies by member state
  (13 in Sweden; 13–16 elsewhere); below it, a parent or guardian must consent.
- For your own household this is ordinary parenting: you decide for your children,
  and Family Beacon's transparency-on-the-child's-device design (no covert mode) is
  built to keep that honest.
- If you host for other families with children, you are handling minors' data for
  people who are not your dependants. Be conservative: get the parents' clear
  agreement, keep the app's transparency intact, and if you are in doubt, do not do
  it without advice. In the US, hosting for other people's under-13s implicates
  COPPA, a separate regime.

---

Practical hosting checklist (both cases, more strictly for others)

Security and operation
- Run the pinned-TLS mode or put the server behind a TLS-terminating reverse proxy
  (Caddy in the reference deployment); never expose plain HTTP to the internet.
- Keep the server, the OS, and the container images updated. Security patching is
  part of "appropriate measures," not optional.
- Restrict who can reach the box (firewall, no stray open ports) and who can log in
  to it (you, with strong auth).

Backups
- The whole server state is one SQLite file. Back it up — and remember the backup
  contains personal data (ciphertext plus metadata). Encrypt backups at rest, store
  them somewhere you control, and prune old ones; do not accumulate forever.

Data discipline
- Keep the admin role an operator role. You cannot read content by design — do not
  add tooling, logging, or "debugging" that tries to. That property is your best
  legal and ethical asset; protect it. (This is also an ETHICS.md hard rule.)
- Turn off or minimise verbose logging that records IPs and timing longer than you
  need. Less retained metadata is less to protect and less to explain.
- Remove departed members' devices promptly (revocation retires their mailboxes and
  clears their records).

Availability — and the safety caveat
- This is a safety app, and a home server is a single point of failure. Be honest
  with the people you host: SOS is best-effort and Family Beacon is not a route to
  emergency services (ETHICS.md → Safety limitations). Hosting for others does not
  make you responsible for their safety, and you should say so — but do keep the
  server actually running, because people may come to rely on it.

The human wrapper (for others)
- A one-page understanding with the people you host beats silence: what you can and
  cannot see, that it is best-effort and not an emergency service, who you will and
  will not share data with (no one), what happens to their data if you stop hosting,
  and how they can leave. Most of this you can lift straight from PRIVACY.md and
  ETHICS.md.

Winding down
- If you stop hosting, tell people first, give them time to move, then delete the
  database and its backups. Do not leave an orphaned copy of other people's data
  lying around.

---

When to get real advice

Talk to someone qualified if you: host for people outside your household at any
real scale; charge money or run it as any kind of service; host for the public;
handle other families' children; or receive a data-subject request, a breach, or a
letter from a regulator you are not sure how to answer. The cost of an hour of
advice is small next to getting one of these wrong.

Sweden: the supervisory authority is IMY (imy.se). Elsewhere, find your national
data protection authority. The European Data Protection Board (edpb.europa.eu)
publishes plain-language guidance on the household exemption, controllers and
processors, and children's data.

---

Relationship to other documents

- PRIVACY.md — normative; the notice you give the people you host can point straight
  at it. Its "Self-hosting and the GDPR" section is the short form of this guide.
- ETHICS.md — the operator-not-surveillant rule and the safety limitations you must
  be honest about.
- ARCHITECTURE.md — the deployment shape (docker compose: sund, ntfy, caddy) and
  what one database file contains.
- ../sund/docs/Sund-PRD.md — the server's threat model: exactly what a host can and
  cannot observe.
