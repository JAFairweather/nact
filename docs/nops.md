# Nops — Nostr server ops (concept)

**Status: concept.** A sibling product to Nact, sharing the same spine. Recorded
so the idea and name have a stake in the ground; not built.

## One line

**Operate your box with your nostr key.** Every server operation — restart a
container, reload Caddy, run a deploy, tail a log — becomes a **signed, scoped,
human-approved, revocable** action with an **on-protocol audit trail**. You
replace *SSH keys + a CI secret* with *your nostr signature + a scoped grant of
ops-authority*.

## Why it exists — the spec generality paying off

We deliberately named the act-side spec **Scoped *Action* Approvals**, not
"Agent Approvals," so that an agent action would be *one type* of action, not the
whole thing (see `scoped-action-approvals.md`). **A server operation is another
type of action.** Nops is that instantiation: the exact propose → approve → sign
→ **enact** spine, with the actuator swapped from "broadcast a nostr event to
relays" (Nact) to "execute a scoped operation on a box" (Nops).

```
                 perceive (data-in)     act (actions-out)
   protocol      Scoped Data Grants     Scoped Action Approvals
   ↳ instances   Nvoy, Nvelope, …       Nact (social) · Nops (server ops)
```

Nact and Nops are **siblings on one spine** — the enact pattern with different
actuators. Both authorize with your signature, both get their policy as scoped
grants, both keep your key off the machine.

## We already built the proto — over the wrong transport

The Nave platform's Ops tooling *is* a server-ops control plane already:
- a curated **verb menu** (status, restart-\*, reload-caddy, show-cron),
- **custom** for the arbitrary/critical tier,
- versioned, reviewable **`deploy/ops/*.sh`** scripts,
- and the **config-as-grant** architecture (`architecture.md`) for how a runner
  gets its policy.

It just runs auth/transport through **GitHub Actions over SSH**. **Nops is that
made nostr-native:** the ops-runner has an nsec, receives its allowed verbs +
policy as a scoped grant from you, and executes a command only after your signed
approval — no GitHub, no SSH keys, no CI secrets.

## Why running shell from nostr isn't insane

Same threat model as Nact (`threat-model.md`); a server op is a **critical-tier
action by default**:

- **WYSIWYS on the command** — you approve the exact string that will run
  (fingerprinted, hidden-character-checked).
- **Scoped verbs, not arbitrary shell** — the curated menu is the allowlist; raw
  shell sits behind sign-on-device, like the critical event kinds.
- **Revocable authority** — rotate the grant and the runner's right to act dies.
- **On-protocol audit** — the approval and the op are signed events; "who ran
  what, approved by whom" is checkable, not a syslog you have to trust.

## The honest read

Narrower and more speculative than Nact. It competes with SSH, Ansible,
Teleport, and CI deploy buttons — mature tools. The wedge is specific but real:
**self-hosters who already live in nostr, want a keyless server (no long-lived
SSH key or CI token to leak), and want infra changes to be human-approved with a
signed audit trail.** For that person it's genuinely better; for everyone else
it's a curiosity. Worth naming and letting breathe — not worth dropping Nact for.

## If it were built

- an **ops-runner** on the box (its own nsec) that receives an *allowed-verbs +
  policy* grant and listens for signed ops-requests;
- verbs defined as reviewable scripts (the `deploy/ops/*.sh` model);
- each request routed through Nact's propose → approve → enact, with the enact
  step being `exec` instead of `publish`;
- the audit trail = the signed request + approval events.

Effectively: **[Nactor](../nactor) — the Nact runtime — with `exec` as the
actuator** instead of publish.
