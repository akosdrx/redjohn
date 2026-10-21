---
name: logic
description: Business logic, race conditions, and mass assignment. The bug is an invariant the application claims and you broke.
---

# Logic

Name the invariant first: a price the server computes, a quantity that cannot go negative, a step that must happen before the next, a field the client is not allowed to set. Then break it. A hunch that "the flow looks odd" is not a finding.

## State machines

Call the later step without the earlier one. Replay a single-use token, coupon, or password-reset link. Walk an order backwards (paid → cart) and see whether the refund, the stock, or the entitlement follows. A client-side-only check is visible in the proxy: send the request the UI will not.

## Races

Two requests in flight, not a loop of sequential retries. The windows that pay off are balance changes, coupon redemption, inventory, vote or like counts, and any "check then write" on a limited resource. Show the before and after: one credit turned into two, or a limit exceeded by a number you can count. A faster response is not a race.

## Mass assignment

Send a field the UI never sends: `role`, `is_admin`, `owner_id`, `price`, `verified`. The finding is the server persisting it and a later request honoring it. An ignored extra field is the control. GraphQL and JSON bodies hide this more often than forms.

## Money and quotas

Negative quantities, decimal rounding, a currency the server does not recompute, and a client-supplied price are worth one request each. Confirm the server stored your value, not that the UI displayed it.

## Agent and tool authority

When the product is itself an agent, the question is which tools and data a prompt can reach. A tool that acts as a user who did not approve the action, a retriever that returns another tenant's documents, or a plugin install path that runs attacker-controlled content is the finding. The prompt text is evidence of the trigger, not the impact.
