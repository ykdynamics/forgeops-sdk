# forgeops-sdk

The ForgeOps capability developer kit: everything needed to write, test and
package a **capability** — one bounded operation (read a status, restart a
service) that a vendor can ask a customer's ForgeOps edge to run, and that the
customer's own policy and approver decide on.

**Status: developer preview, not released yet.** The API, the CLI and the
manifest format may still change between preview releases; each release states
what changed and how to move.

## What is here

| Package | What it is |
| --- | --- |
| `sdk` | Write a capability in Go: bind its input, return its output, report progress, refuse cleanly. It serves the runtime contract below. |
| `sdk/egress` | Outbound calls limited to the destinations a capability declares. Cooperation within the process, not a sandbox. |
| `runtimecontract` | `runtime.v1`, the wire contract between an edge and a capability, with a client. A capability written from the contract alone, without the SDK, works the same. |
| `capability` | The `capability.v1` package document: types, validation and compatibility rules. |
| `buildrecipe` | The one recipe that builds a capability's executable bytes, for an explicit platform and compiler, so its digest is reproducible. Experimental API. |
| `cmd/forgeops-cap` | The CLI: `init`, `validate`, `run`, `package`, `selfcheck`. |

## Quick start

With a release (once published):

```bash
go install github.com/ykdynamics/forgeops-sdk/cmd/forgeops-cap@<release>
forgeops-cap init example.service.status
cd example-service-status
forgeops-cap validate capability.yaml
forgeops-cap run . --input '{"service":"example"}'
```

Before a release, from a checkout of this repository:

```bash
go build -o forgeops-cap ./cmd/forgeops-cap
./forgeops-cap init example.service.status --sdk-replace "$PWD"
```

`init` writes a project that requires this SDK and pins the compiler it is
qualified with (`toolchain` in `go.mod`), because a capability's digest is only
reproducible under the compiler that built it.

## What a local run proves, and what it does not

- `forgeops-cap run` proves your capability builds and answers its contract on
  your machine.
- `forgeops-cap selfcheck` proves this toolkit works on your machine, with its
  own sample. It does not check your capability.
- Neither grants anything. What may run on a customer's edge is decided there,
  by the customer's policy and approver. A package records exactly which bytes
  were built (`identity.artifactDigest`, for a declared platform); the edge
  checks the bytes it is given against that digest.

## Supported platforms

The first preview is qualified on Linux amd64 and Linux arm64. macOS
workstation binaries are planned once tested.

## License

Apache License 2.0; see [LICENSE](LICENSE).
