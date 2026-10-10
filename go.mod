module github.com/ykdynamics/forgeops-sdk

go 1.23

// The compiler is part of an implementation identity: a pinned digest does not
// reproduce under a different Go version (ADR-010). Staging keeps the private
// repository's pin; the preview release records its own, checked choice.
toolchain go1.23.12

require gopkg.in/yaml.v3 v3.0.1
