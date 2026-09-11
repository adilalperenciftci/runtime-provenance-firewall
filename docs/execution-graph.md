# Execution graph

`rpf graph-events` now reconstructs the deterministic graph directly from a strictly validated
canonical stream and creates a new canonical graph file without overwriting an existing one.
The privileged sensor smoke test exercises this path with real exec telemetry.

The graph is a deterministic projection of verified events, not a separate source of truth.
Nodes use composite process keys. Edges state only what the event supports:

- `observed_exec_parent`: parent identity was associated with child at exec;
- `unobserved_exec_parent`: kernel supplied a parent identity absent from the captured graph;
- `file_open_sensitive`: process opened a categorized sensitive path;
- `file_open_output`: process opened an output for writing;
- `file_rename_output`: process renamed a path into the output root;
- `network_connect`: process attempted a connection to a numeric destination;
- `artifact_finalized`: collector associated final artifact digest with an observed process.

No edge is named `caused`. A write-open does not prove bytes were written, and ancestry does
not prove semantic influence. Nodes and edges are sorted before hashing, so replay yields the
same graph digest for the same verified stream.

Graph schema v0.2 labels every node's `parent_observation` as `observed`, `unobserved`, or `none`.
An exec edge uses `observed_exec_parent` only when its source node exists; otherwise it uses
`unobserved_exec_parent`. This prevents consumers from mistaking a kernel-reported parent key for
a fully reconstructed ancestor. It does not infer whether the missing parent was outside the
cgroup, started before the sensor, or was lost.

The M6 laboratory graph now contains both `file_open_output` and `artifact_finalized` edges for
an exact absolute artifact path. This supports observed write-open attribution; it does not turn
the two observations into proof that the process supplied every final byte.
