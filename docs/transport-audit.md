# Aether transport audit

This document tracks the hardening of Aether's existing transports. The current scope intentionally excludes server-dependent transports and new protocol families. The goal is to make MASQUE H3, MASQUE H2, WireGuard, WARP-in-WARP, the scanners, and the local netstack reliable before expanding the architecture.

## Invariants

A transport is not ready merely because a process, socket, TLS session, QUIC connection, or WireGuard handshake exists.

Aether exposes SOCKS only after the selected transport has completed its control-plane acceptance and, unless explicitly disabled, repeated end-to-end data-plane confirmation.

A runtime component ending unexpectedly is an error. Tunnel, forwarder, netstack, and SOCKS lifecycles are supervised together rather than detached.

User-provided timing, buffer, fragmentation, and noise settings are bounded before use.

## MASQUE HTTP/3

Status: hardened in the current `main` branch.

- CONNECT-IP is accepted only after a numeric 2xx response.
- SOCKS is not exposed before CONNECT-IP acceptance, including when data-plane validation is disabled.
- CONNECT-IP stream reset or premature finish is treated as failure.
- Malformed capsules and malformed HTTP datagrams are surfaced instead of silently ignored.
- Keepalive cadence uses the configured health interval.
- QUIC idle timeout is derived from bounded health settings.
- Data-plane probes start only after control-plane acceptance.
- Socket buffer setup failures are diagnostic rather than silent.

Manual validation:

1. H3 successful connection and browsing.
2. H3 control-plane success with dropped datagrams must never report ready.
3. Forced non-2xx CONNECT-IP response must fail.
4. Network loss must eventually terminate the tunnel and trigger recovery.
5. IPv4, IPv6, and dual-stack scans where available.

## MASQUE HTTP/2

Status: hardened in the current `main` branch.

- Resource-tier flow-control windows and send buffers are bounded.
- Fallback defaults are clamped even when a dependent minimum changes.
- Server push is disabled and received header size is bounded.
- CONNECT-IP must return a successful HTTP status.
- PING/PONG health uses the configured interval, timeout, and failure budget.
- Capsule parser, flow-control release, probe, body, capacity, and stream errors propagate.
- Unexpected CONNECT-IP stream closure triggers recovery.
- ClientHello fragmentation is limited to the initial client flight.

Manual validation:

1. Throughput ramp and sustained throughput.
2. Long idle connection followed by traffic.
3. Forced TCP loss and reconnect.
4. Fragmentation enabled and disabled.
5. CPU and memory while transferring a large file.

## WireGuard

Status: hardened in the current `main` branch.

- Receive, send, timer, and health task failures terminate the tunnel.
- Startup timeout and established-session stale timeout are separate.
- Socket and channel errors are propagated.
- Data-plane validation requires repeated confirmations.
- Probe resend scheduling is monotonic and bounded.
- Post-handshake junk is emitted once per local socket rather than on the packet hot path.
- Keepalive junk cannot overlap for the same local socket.
- Endpoint scanning covers IP and port combinations instead of pairing each IP with only one port.
- Anchor endpoints are tested first and range candidates are interleaved.
- CIDR inputs are normalized and prefix lengths are validated.

Manual validation:

1. Turbo, balanced, thorough, stealth, and ironclad scans.
2. Confirm selected endpoint port is the port that passed validation.
3. Upload and download after at least one rekey interval.
4. Suspend/resume and interface change.
5. Forced endpoint packet loss and stale-session recovery.

## WARP-in-WARP / gool

Status: lifecycle-hardened in the current `main` branch.

- Outer WireGuard, UDP forwarder, inner WireGuard, and SOCKS are one supervised runtime.
- Failure or completion of any component cancels the remaining components.
- Startup failure of the inner tunnel cannot leave the outer tunnel detached.
- UDP forwarder accepts one local inner peer and rejects sender changes.
- Inner MTU is asserted to remain lower than outer MTU.
- Repeated outer endpoint failures cause rescanning.

Manual validation:

1. Successful outer validation, inner validation, and browsing.
2. Kill outer traffic and verify SOCKS is removed before reconnect.
3. Kill inner traffic and verify the complete stack restarts.
4. Long transfer with no fragmentation loop or MTU black hole.
5. Repeated reconnects without task, socket, or memory growth.

## Local netstack and SOCKS

Status: hardened in the current `main` branch.

- TCP pending data and generated packet queues are bounded.
- TCP connect and SOCKS negotiation have deadlines.
- TCP half-close is propagated after pending data drains.
- UDP associations close explicitly and expire after bounded inactivity.
- DNS requests validate transaction ID, response flags, requested record type, and responder.
- DNS netstack sockets close after each query.
- SOCKS authentication negotiation verifies that `NO AUTH` was offered.
- UDP ASSOCIATE pins its first client endpoint.
- Invalid prefixes and invalid MTU values are rejected.
- Tunnel channel failure terminates the netstack instead of leaving a ghost listener.

Manual validation:

1. TCP browsing, large downloads, and upload-heavy traffic.
2. Domain, direct IPv4, and direct IPv6 SOCKS targets.
3. UDP DNS and application UDP through SOCKS.
4. Hundreds of short DNS/TCP sessions without resource growth.
5. Slow consumer and abrupt client disconnect behavior.

## Noise and fragmentation

Status: bounded, with existing defaults preserved.

- Junk count, packet size, signature size, interval, fragment size, and fragment delay have hard bounds.
- Noise emission stops on the first socket send failure.
- Fragmentation ends when the server response phase begins.
- No additional noise profiles were added during this audit.

Noise and fragmentation remain optional compatibility tools, not proof of censorship resistance.

## Dependency policy

Dependency versions are not changed solely because a newer version exists.

Major upgrades for BoringSSL bindings, Tokio-Boring, smoltcp, quiche, or WireGuard implementations require an isolated compatibility pass, Windows release build, targeted protocol tests, and before/after runtime measurements. The current audit fixes correctness against the APIs already used by the repository and defers risky dependency migration until the hardened baseline passes manual validation.

## Required validation command

From Aether-GUI on Windows:

```powershell
git pull origin main
pnpm dev:custom
```

The local wrapper synchronizes the embedded Aether submodule, builds the release core, installs it into the GUI core registry, selects it, and starts the GUI.

Runtime or compiler errors found during this validation must be fixed with focused tests based on the reproduced failure. No automatic CI workflow is required for this process.
