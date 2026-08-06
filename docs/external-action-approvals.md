# External frozen-action approvals

Nact can approve an action whose signing key and actuator live in another runtime. This is the
approval surface used by Nvoy's Codex and Claude participants; Nact never receives their keys and
never publishes their replies.

1. An activated participant NIP-98-authenticates `POST /api/propose-external` as itself. The closed
   body names one runtime instance, 128-bit proposal ID, frozen event fingerprint, readable action,
   recipient context, and an expiry of at most fifteen minutes. It contains no callback URL,
   approver, signer, relay, or publication target.
2. Nact durably stores and fsyncs the inert proposal. The Queue renders the exact message, recipient
   context, complete seal fingerprint, participant identity, and expiry.
3. The Director signs one kind-27235 event whose `u` is
   `nvoy://outbound/<instance>/<proposal-id>` and whose payload hash commits to canonical JSON:
   `{proposal_id,fingerprint,verb}`. That event itself authenticates `POST /api/decide-external`;
   there is no second generic signer prompt.
4. Nact verifies the closed event schema, Director key, freshness, URL, method, payload hash, event
   ID, and signature, then fsyncs the exact signed event. It stores no unsigned approval boolean.
5. The same activated participant retrieves only its own result through
   body-bound `POST /api/external-approval` with `{proposal_id}`. The external runtime independently verifies the
   Director signature and fingerprint immediately before opening its signer.

Proposal ID reuse with different bytes, cross-participant collisions, foreign/stale/future
decisions, mutation, expiry, and repeated decisions fail closed. Revocation of participant
activation prevents new submissions and retrieval; the external runtime separately rechecks its
live action-grant chain before signing.
