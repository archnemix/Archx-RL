# Product scope

Purpose: keep Archx focused on the identification and rate-limiting layer requested by the user.

## What we are making

- A developer-configurable layer between a frontend and a server that evaluates request signals, relates observations probabilistically and applies rate limits. Host applications must call it and enforce its decisions.
- Configurable signal requirements, thresholds, limits and friendly denial/error messages; decisions are context, not proof that two requests are from one person.
- Optional, refreshable IP threat intelligence and optional Cloudflare Turnstile verification, with operator-controlled enforcement and documented false-positive/failure behavior.
- Privacy controls: device signals are hashed for server storage; the operator chooses hashed or raw IP retention. Identifiers can still be processed transiently and need consent, retention and logging controls.
- Optional application-layer encryption in addition to HTTPS, using an independently trusted server public key, with short-lived single-use challenges and honest limits on replay and trusted client code.
- Platform-appropriate clients and developer integration examples as they are actually implemented and tested. Linux native collection and a browser encrypted transport for caller-supplied signals currently exist; browser JavaScript cannot read Linux hardware IDs.

## What we are not making

- A bank or banking application, payment processing or other unrelated business product.
- An account, login, authentication, authorization or identity-verification system; a matching signal is not a credential or proof of a unique person/device.
- A subscription, trial, entitlement or licensing system. A host may choose to build those separately in the future; they are not Archx's current job.
- A promise to stop every attacker, identify every individual, eliminate false positives, prevent all first-use replay races, or defeat a party that can replace trusted code or keys.
- A claim that the prototype, C core, every frontend/OS, distributed deployment, live Cloudflare integration or production security review is already complete.
