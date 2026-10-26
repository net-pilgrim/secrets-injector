# TODO: Split Architecture (Sidecar Fetcher + tmpfs Transport + Reader Shim)

## Context & Objective

Evaluate and merge the split-design architecture in coordination with [zeller](https://github.com/net-pilgrim/zeller).

In this model, the secrets injector is split into two distinct components:
1. **Sidecar / Init Container (Fetcher)**: Holds the vault token (`SECRETS_FETCH_KEY`), egress network access, TLS certificates, and HTTP client. It retrieves secrets from the vault and writes them to a memory-backed volume (`emptyDir: { medium: "Memory" }` or `/dev/shm`) with restricted permissions (e.g. mode `0400`).
2. **Application Shim (Reader)**: An ultra-lightweight `LD_PRELOAD` constructor running inside the application container that reads the secrets file directly from the tmpfs path, populates `environ`, intercepts `getenv`, and optionally scrubs/unlinks the file.

---

## Key Benefits

- **Token Isolation**: The vault master token (`SECRETS_FETCH_KEY`) never enters the application container.
- **Zero Egress from App Container**: Application container requires no network egress to the vault. NetworkPolicies can completely isolate the application pod network.
- **Zero In-Process TLS/HTTP in App**: The shim requires no networking logic or HTTP client in the application process.
- **Kubernetes Native Sidecar Ordering**: Native sidecars (`restartPolicy: Always` in `initContainers`) support startup probes (e.g., passing once `/dev/shm/secrets.json` exists) to guarantee secrets are written before the application container starts.

---

## Action Items

- [ ] **Reader Mode in Shim (`src/injector.zig`)**:
  - Support `SECRETS_FILE` or `file://` scheme in `SECRETS_VAULT_URL`.
  - When configured, bypass HTTP fetching entirely and parse secrets directly from the local tmpfs path using `json_parser.zig`.
  - In-place memory scrubbing and optional file unlinking after loading.
- [ ] **Integration with [zeller](https://github.com/net-pilgrim/zeller)**:
  - Coordinate with the mutating webhook operator in `zeller` to automatically inject:
    - Shared memory-backed `emptyDir` volume (`medium: Memory`, with appropriate `sizeLimit`).
    - Sidecar container definition with vault credentials, startup probe, and egress rules.
    - `LD_PRELOAD` and `SECRETS_FILE` environment variables into target application containers.
- [ ] **Permissions & Lifecycle Verification**:
  - Validate non-root UID/GID and `fsGroup` compatibility for reading `0400` files across vendor base images.
  - Verify memory limits and tmpfs accounting against container limits.
  - Document secret rotation considerations (runtimes snapshot `environ`, requiring pod restart or signal-driven reload).
