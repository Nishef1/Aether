# Custom Fork Patch Ledger

**Migration branch:** `aether-v2-custom-migration`  
**Canonical upstream:** `CluvexStudio/Aether v2.0.0` at `0e6f6a5218e65ed4cddc68d1a71d9b9633f89e3f`  
**Previous custom head:** `21fd143031f42e123acc00b9e1b5432bcb918bcc`  
**Previous baseline:** `v1.9.0` at `311b573352bb67e494895ff67d20b002d075116a`

This file is the removal/port ledger for every commit that existed between the
old v1.9 baseline and the old custom head. v2 is the source of truth. A custom
change survives only when v2 does not already provide the same or better
behavior.

Status vocabulary:

- **ADOPT UPSTREAM** — v2 already has the behavior or a better implementation.
- **KEEP/PORT** — custom behavior remains valuable and is carried onto v2.
- **REWORK** — keep the intent, but implement it against v2 architecture.
- **DROP/SUPERSEDED** — historical/config/docs change with no v2 patch to retain.

## P001 — Scanner/reconnect foundation

**Old commits:**  
`fb6346c05bfa`, `d391f25d86e9`, `f4b1686ce54a`

**Decision:** REWORK

v2 already carries the useful bounded scanner/port-wave work, including
WireGuard `pool_port_waves`, broader scanner fixes, endpoint cooldown and
resource-aware scan behavior. Do not replay the v1.9 scanner wholesale.

Retain only behavior that v2 still lacks and that remains justified elsewhere in
this ledger:
- scan-mode probe jitter is supplied by P010;
- network-scoped recent-path intelligence is supplied by P002;
- dual-stack interleaving is supplied by P007.

The old cheap prefilter stays dropped unless a new v2 benchmark proves it
improves time-to-protected without introducing false negatives.

**Removal condition:** all residual behavior is represented by P002/P007/P010.  
**Tests:** scanner candidate coverage, Turbo first-success, IP-family ordering.

## P002 — Historical docs/version churn

**Old commits:**  
`39971070f69e`, `d3baeacf83ec`, `ca66cd230bfe`

**Decision:** DROP/SUPERSEDED

These commits changed old README/version baselines. v2 owns version `2.0.0`
and its current documentation.

**Removal condition:** immediate.  
**Tests:** package version comes from v2 Cargo metadata.

## P003 — Network-scoped Path History

**Old commits:**  
`abd9d0e90075`, `279651938724`, `14f47beccf17`, `d119996c7021`,
`254a13dd9f9c`, `9aeacd33b8ba`, `82546e05672a`, `340efa27e567`,
`6942ebc2040d`, `6818ef7134dd`

**Decision:** KEEP/PORT

v2 keeps one last connection and an in-process endpoint cooldown, but it does
not provide the bounded, network-scoped history model from the custom fork.
Preserve:
- bounded persistent history;
- live underlay fingerprint preferred over a launch hint;
- verified runtime-path recording;
- last-known-good/history ordering;
- failure cooldown/recency;
- transport/profile awareness;
- rescue diversification.

Do not replace v2's own generic endpoint cooldown; Path History should augment
ordering and persistence, not become a second transport engine.

**Files expected:** `path_history.rs`, targeted integration in `lib.rs` and
connection-success/failure paths.

**Removal condition:** upstream gains equivalent network-scoped persistent path
history and selection hooks.  
**Tests:** network isolation, bounded history, success/failure accounting,
live-underlay precedence, no cross-network reuse.

## P004 — Transaction-safe DNS validation

**Old commits:**  
`a6ae6f8ed1f2`, `6f8c8a9b17b5`, `40ec96f2cfa7`, `af2f69c402ab`,
`c8d8c860770d`

**Decision:** ADOPT UPSTREAM

v2 has shared DNS response matching and tests that reject wrong transaction IDs
in both `dns.rs` and `socks.rs`. Do not port the old protocol-specific
copies.

**Removal condition:** immediate.  
**Tests:** keep upstream DNS transaction/name/type matching tests.

## P005 — Deterministic H2 compatibility masks

**Old commits:**  
`42a216fe820c`, `ed26e39cf5ec`, `b52611ad78cd`, `6d9b3ac09fc4`,
`06a2bb16b5e9`, `ac92b4052779`, `56c3d402d936`

**Decision:** KEEP/PORT

v2 still exposes only legacy randomized TLS ClientHello fragmentation. Port the
mode abstraction on top of v2:
- off;
- legacy TCP fragmentation;
- deterministic ClientHello split;
- Patterniha experimental shaping.

Preserve deterministic boundaries across short writes and compatibility with
the existing legacy boolean/Android bridge sentinels.

**Removal condition:** upstream provides equivalent deterministic modes and
backward-compatible configuration.  
**Tests:** env parsing, legacy compatibility, short-write stability, bounded
record shaping, off mode byte transparency.

## P006 — Named TLS policy profiles

**Old commits:**  
`389af6ef48d2`, `f834a626ebbf`, `8206c5807424`

**Decision:** REWORK

v2 has improved TLS internals, pin verification, QUIC v2 bait and
`AETHER_TLS_GROUPS`, but no named `AETHER_TLS_PROFILE` policy. Keep named
profiles only as a thin policy layer that resolves to v2 TLS settings/groups.
Do not replace v2 `tls.rs` wholesale.

**Removal condition:** upstream exposes equivalent named policy/capability
surface.  
**Tests:** profile parsing, explicit groups override profile defaults, H2/H3
share policy without bypassing v2 verification.

## P007 — Quick-reconnect failure lifecycle

**Old commits:**  
`ae6bf9b3ad7f`, `52312fa40c7f`

**Decision:** REWORK

v2 now owns generic quick reconnect and endpoint cooldown. Do not port the old
v1.9 state machine. Preserve only the network-scoped failure/abandonment
semantics through P003 so a stale attempt cannot poison another underlay.

**Removal condition:** P003 fully covers network-scoped failure history.  
**Tests:** abandoned attempts expire; failed cached route does not immediately
win again on the same network.

## P008 — Dual-stack candidate interleaving

**Old commits:**  
`b5b825bafd71`, `39dc857525f3`

**Decision:** KEEP/PORT

v2 still builds the IPv4 candidate body before the IPv6 body when both families
are selected. Reintroduce fair v4/v6 interleaving without changing each
family's internal priority or port-wave rules.

**Removal condition:** upstream interleaves dual-stack candidates itself.  
**Tests:** `both` contains both families near the front; v4-only/v6-only order
is unchanged; no duplicates are introduced.

## P009 — Distinct obfuscation profiles

**Old commit:** `ef547df52a97`

**Decision:** ADOPT UPSTREAM

v2 already has distinct light/balanced/aggressive behavior and regression tests
for both MASQUE noize and AetherNoize. Do not port the old implementation.

**Removal condition:** immediate.  
**Tests:** retain upstream profile-distinctness tests.

## P010 — Platform route import compatibility

**Old commit:** `34eaabc941c4`

**Decision:** DROP/SUPERSEDED

v2 reorganized networking/egress and is the canonical compile target. Do not
carry the old conditional-import patch unless a v2 target actually fails.

**Removal condition:** immediate.  
**Tests:** v2 CI target matrix.

## P011 — Scan-aware adaptive runtime defaults

**Old commits:**  
`e66fb9e16b4f`, `394c03e7dedc`

**Decision:** KEEP/PORT

v2 has no `AETHER_PROBE_JITTER_MS` or equivalent scan-mode policy layer.
Port the adaptive module after v2 CLI parsing. Explicit user values always win.

Policy areas:
- MASQUE startup/liveness;
- H2 keepalive interval/timeout;
- H3 keepalive interval after P012 rework;
- WG stale detection;
- endpoint cooldown;
- probe jitter;
- one conservative WG/WiW persistent-keepalive default.

**Removal condition:** upstream gains an equivalent scan-mode policy layer.  
**Tests:** explicit overrides win; Turbo is fail-fast; Stealth reduces churn;
Thorough keeps the pool recoverable.

## P012 — Activity-aware liveness and keepalive

**Old commits:**  
`041e99ed0f0d`, `7471e43dd9b6`, `4c6580b247a3`, `faac4f3bcea4`,
`d50a550dfb17`, `088e82f32b09`

**Decision:** REWORK

v2 improved WG health checking and exposes H2 keepalive configuration, so do not
replay the old files wholesale. v2 H2 and H3 still use periodic timers rather
than suppressing keepalives during recent application activity.

Keep:
- standard conservative WG/WiW idle keepalive policy from P011;
- configured keepalive parity across WiW hops;
- activity-aware H2/H3 keepalive where it can be added without fighting v2
  lifecycle code.

Adopt v2:
- WG stale/valid-RX health logic;
- v2 transport/reconnect structure.

**Removal condition:** upstream transports become activity-aware and use one
consistent WG/WiW keepalive policy.  
**Tests:** active traffic suppresses redundant keepalive; idle tunnel still
probes; configured WG keepalive reaches every WiW hop.

## P013 — Privacy-safe Ironclad HTTP probe

**Old commit:** `f1fc3d5a7ee3`

**Decision:** KEEP/PORT

v2 still sends `User-Agent: aether-ironclad` to the public probe target. Remove
the product-branded header while preserving the real data-plane HTTP check.

**Removal condition:** upstream probe is unbranded.  
**Tests:** request contains no `aether` branding and still validates the
expected HTTP status.

## P014 — Failed WiW pair cooldown

**Old commit:** `21fd143031f4`

**Decision:** REWORK

v2 has generic endpoint cooldown for failed WireGuard reconnects, but the nested
WiW case needs pair-aware rotation so a failed outer/inner pair does not
immediately reappear as the next pair. Implement this against v2's existing
cooldown/exclusion flow instead of restoring the old global state verbatim.

**Removal condition:** upstream cooldown is explicitly pair-aware for WiW.  
**Tests:** failed pair is excluded together on the next rescan; expiry restores
eligibility; one-hop pinned cases keep the pinned hop semantics.

## Coverage audit

All 47 commits between `311b573...` and `21fd143...` are assigned above.
No old commit may be cherry-picked onto v2 without first mapping it to one of
these entries.
