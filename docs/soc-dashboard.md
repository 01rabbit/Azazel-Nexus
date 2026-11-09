# Optional SOC read layout

Refs #415. The overview and incident screens offer an optional layout toggle;
classic presentation is the default on reload and after logout. This is a
browser presentation of existing read-model sections. It adds no endpoint,
read leaf, daemon request, writable store, dependency or polling loop.

The overview adds cards for retained-list coverage, Edge intake freshness,
audit, Knowledge Lite and M.I.O. advisory status. Existing access/status
vocabulary is retained. A retained row count is not the total open count or an
execution count. Existing four-question summary remains authoritative for the
operator's high-level interpretation. No history is supplied by this read
model, so the UI explicitly says unavailable rather than manufacturing trends.

The incident table sorts by supplied severity (lower is higher priority) or
last observation, filters open rows, and displays at most 100 retained rows.
The current read model does not supply observed source addresses; the table
states that absence. It shows Edge **would**, never executed controls. The
selected incident ID survives refresh and filtering while retained; a missing
selection is explicit and never attached to a different incident. Details reuse
the existing incident renderer and preserve its separate facts, guidance,
model advice, citations, provenance and unavailable statuses. Filter/button
focus is restored across refresh. Logout clears all selection and layout state.

Focused software and browser fixture checks verify these mechanics and the
existing login/session/CSP/read-leaf boundaries. They do not establish human
operator benefit, target memory/resource budgets, HG-05, production model
admission or a hardware-supported configuration. Counterbalanced held-out
operator tasks and existing target gates in #415 remain open.
