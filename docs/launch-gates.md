# Launch Gates

The machine vocabulary in [../gates.json](../gates.json) separates gates that block a complete local handoff from gates that block launch. [output-inventory.md](output-inventory.md) explains the same IDs and acceptance criteria for humans.

## Gate Rule

A generated packet can identify a gate. It cannot clear the gate by itself.

Each gate needs the evidence and evaluator declared for its ID. A local verifier pass is not production or launch approval: launch additionally requires accepted human evidence for every gate whose `blocking` value is `launch`, including target, hardening, deployment, rollback, and go/no-go decisions.

An external blocker remains blocked; it is not accepted launch evidence. An accepted exception must name its accepter, reason, scope, and evidence.
