# Secrets Injector (`libsecrets_injector.so`)

A lightweight, high-performance secrets injector written in **Zig** that uses Linux `LD_PRELOAD` to dynamically and transparently inject secrets from a web vault into any binary at runtime.

When preloaded into a process, the library authenticates against a web vault using an initial `SECRETS_FETCH_KEY`, retrieves secrets, synchronizes them into the process environment, intercepts `getenv` / `secure_getenv`, and immediately scrubs the initial fetch key from process memory to prevent credential leakage.

---

## Table of Contents

- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Supported Vault Adapters](#supported-vault-adapters)
  - [Bitwarden Secrets Manager](#1-bitwarden-secrets-manager)
  - [1Password Connect](#2-1password-connect)
  - [HashiCorp Vault (KV v1 & v2)](#3-hashicorp-vault-kv-v1--v2)
  - [Generic REST & Dotenv](#4-generic-rest--dotenv)
- [Configuration Reference](#configuration-reference)
- [Runtime & Language Compatibility](#runtime--language-compatibility)
- [Security Considerations](#security-considerations)
- [Prerequisites & Building](#prerequisites--building)
- [Usage Examples](#usage-examples)
  - [Local Application](#local-application)
  - [OCI Container & Sidecar (Zero Image Changes)](#oci-container--sidecar-zero-image-changes)
    - [1. Kubernetes (Init Container - Recommended)](#1-kubernetes-init-container---recommended)
    - [2. Kubernetes (Native Sidecar - K8s 1.28+)](#2-kubernetes-native-sidecar---k8s-128)
    - [3. Docker Compose](#3-docker-compose)
    - [4. Standalone Docker CLI](#4-standalone-docker-cli)
  - [Embedding into Application Dockerfile](#embedding-into-application-dockerfile)
- [Testing](#testing)
- [Project Structure](#project-structure)

---

## Key Features

- **Transparent Libc Interception**: Intercepts `getenv`, `secure_getenv`, and `__secure_getenv` with zero application code changes.
- **Universal Runtime Support**: Synchronizes secrets into `environ` at process startup so runtimes that snapshot environment variables (Python's `os.environ`, Node.js `process.env`, Go, Rust, Ruby) receive the secrets automatically.
- **Automatic Schema Detection**: Native support for Bitwarden Secrets Manager, 1Password Connect, HashiCorp Vault (KV v1 & v2), flat JSON, and raw dotenv formats without manual configuration.
- **Fetch Key Scrubbing**: Automatically zeroes out memory bytes of `SECRETS_FETCH_KEY` in `environ` and calls `unsetenv` before the target application's `main()` executes.
- **Recursion & Re-entrancy Safe**: Thread-local execution guards prevent infinite recursion loops during dynamic linking, libc symbol resolution, or internal `libcurl` calls.
- **Lock-Free Lookups**: Read-only hash table lookups during application runtime introduce zero mutex contention or locking overhead.
- **Small Footprint**: Compiled with Zig in `ReleaseSmall` mode to an ultra-compact ~199 KB shared library.

---

## How It Works

```
                               Target Process Launch
                                         │
                                         ▼
                      Dynamic Linker (ld.so) loads library
                                         │
                                         ▼
               ELF Constructor (.init_array) executes before main()
                                         │
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
        No SECRETS_FETCH_KEY set                 SECRETS_FETCH_KEY found
                     │                                       │
            Passthrough mode                                 ▼
         (Zero-overhead passthru)                 HTTP GET to SECRETS_VAULT_URL
                                                  (Bearer / X-Vault-Token)
                                                             │
                                                             ▼
                                                  Auto-detect vault schema
                                                  (Bitwarden, 1Password, etc.)
                                                             │
                                                             ▼
                                                  Populate in-memory store
                                                  (std.StringHashMap)
                                                             │
                                                             ▼
                                                  Sync to environ via setenv()
                                                             │
                                                             ▼
                                                  Zero out & scrub fetch key
                                                             │
                                                             ▼
                                                Target process main() runs
                                                             │
                                         ┌───────────────────┴───────────────────┐
                                         ▼                                       ▼
                             Call getenv("SECRET_KEY")               Call getenv("PATH")
                                         │                                       │
                                   Found in store                         Not in store
                                         │                                       │
                               Returns injected value                  Delegates to real libc
```

---

## Supported Vault Adapters

The injector automatically detects the response schema returned by the vault:

### 1. Bitwarden Secrets Manager

[Bitwarden Secrets Manager (BWS)](https://bitwarden.com/products/secrets-manager/) uses machine access tokens (`0.xxxx.yyyy`).

**Response Schema (`GET /secrets` or `POST /secrets/search`):**
```json
{
  "data": [
    {
      "id": "73e97022-b5e0-49ec-85d9-4fa2210ffbe9",
      "organizationId": "00000000-0000-0000-0000-000000000000",
      "key": "DATABASE_URL",
      "value": "postgres://user:secret@localhost:5432/mydb"
    },
    {
      "id": "84a12345-0000-0000-0000-000000000000",
      "key": "API_KEY",
      "value": "bw_live_token_xyz"
    }
  ]
}
```

**Usage:**
```bash
SECRETS_VAULT_URL="https://vault.bitwarden.com/api/secrets" \
SECRETS_FETCH_KEY="0.your_bitwarden_access_token..." \
LD_PRELOAD="./bin/libsecrets_injector.so" \
./your_binary
```
*(For self-hosted instances or EU cloud, point `SECRETS_VAULT_URL` to your server, e.g. `https://api.bitwarden.eu/secrets`)*.

---

### 2. 1Password Connect

[1Password Connect API](https://developer.1password.com/docs/connect/) exposes vault items over HTTP (`op-connect-api`).

**Response Schema (`GET /v1/vaults/<VAULT_ID>/items/<ITEM_ID>`):**
```json
{
  "id": "item-abc-123",
  "title": "Production Config",
  "vault": { "id": "vault-xyz" },
  "category": "SERVER",
  "fields": [
    {
      "id": "username",
      "label": "DB_USER",
      "value": "admin"
    },
    {
      "id": "password",
      "label": "DB_PASSWORD",
      "value": "supersecretpassword"
    },
    {
      "id": "custom",
      "name": "API_TOKEN",
      "value": "ops_token_999"
    }
  ]
}
```
*The injector extracts `fields[].label` (or `fields[].name`), while ignoring envelope metadata (`id`, `title`, `vault`).*

**Usage:**
```bash
SECRETS_VAULT_URL="http://connect-api:8080/v1/vaults/<VAULT_ID>/items/<ITEM_ID>" \
SECRETS_FETCH_KEY="eyJhbGciOi..." \
LD_PRELOAD="./bin/libsecrets_injector.so" \
./your_binary
```

---

### 3. HashiCorp Vault (KV v1 & v2)

Supports both HashiCorp Vault KV version 1 (`data: { ... }`) and version 2 (`data: { data: { ... } }`).

**Response Schema:**
```json
{
  "data": {
    "data": {
      "DATABASE_URL": "postgres://user:pass@localhost:5432/app",
      "REDIS_URL": "redis://127.0.0.1:6379"
    },
    "metadata": { "version": 2 }
  }
}
```

**Usage:**
```bash
SECRETS_VAULT_URL="http://127.0.0.1:8200/v1/secret/data/my-service" \
SECRETS_FETCH_KEY="hvs.CAES..." \
LD_PRELOAD="./bin/libsecrets_injector.so" \
./your_binary
```

---

### 4. Generic REST & Dotenv

If your vault returns a flat JSON dictionary or line-separated `.env` strings, it is automatically parsed:

**Flat JSON:**
```json
{
  "DATABASE_URL": "postgres://...",
  "API_KEY": "sk_test_..."
}
```

**Dotenv / Raw Text:**
```
DATABASE_URL=postgres://...
API_KEY=sk_test_...
PORT=8080
```

---

## Configuration Reference

All settings are configured via environment variables:

| Variable | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| `SECRETS_FETCH_KEY` | **Yes** | Authentication secret/token passed to the vault. | *(None)* |
| `SECRETS_VAULT_URL` | No | Full URL endpoint of the secrets vault. | `http://127.0.0.1:8080/secrets` |
| `SECRETS_AUTH_HEADER` | No | Custom header name (e.g. `X-Custom-Auth`). By default sends both `Authorization: Bearer` and `X-Vault-Token`. | *(Default headers)* |
| `SECRETS_VAULT_TIMEOUT` | No | Total network timeout in seconds. | `5` |
| `SECRETS_VAULT_INSECURE`| No | Set to `1` to disable SSL certificate verification (testing only). | `0` |
| `SECRETS_INJECTOR_SCRUB`| No | Set to `0` to prevent scrubbing `SECRETS_FETCH_KEY` from process memory. | `1` *(scrub enabled)* |
| `SECRETS_INJECTOR_DEBUG`| No | Set to `1` to print diagnostic messages to `stderr`. | `0` |
| `SECRETS_INJECTOR_FAIL_FAST` | No | Set to `1` to exit immediately with code `1` if fetching secrets fails. | `0` |

---

## Runtime & Language Compatibility

Because the injector hooks standard libc (`getenv`, `secure_getenv`) and updates `environ` via `setenv`:

- **C / C++**: Calls to `getenv("SECRET")` return the injected secret.
- **Python**: `os.getenv("SECRET")` and `os.environ["SECRET"]` work immediately.
- **Node.js**: `process.env.SECRET` is populated at startup.
- **Go**: `os.Getenv("SECRET")` reads from the preloaded environment.
- **Rust**: `std::env::var("SECRET")` works out of the box.
- **Bash / Dash / Zsh**: Environment variables are expanded in child shells.

---

## Security Considerations

1. **Zeroing Master Credentials in Memory**:
   Rather than only calling `unsetenv()`, the library performs an in-place `@memset` of the variable's bytes in the `environ` pointer array before unsetting it. This mitigates exposure via memory dumps or `/proc/self/environ`.

2. **Hidden Fetch Key**:
   Even if the target process explicitly calls `getenv("SECRETS_FETCH_KEY")`, the hook intercepts the query and returns `NULL`.

3. **No Lock Contention**:
   The internal secrets dictionary is populated once during library initialization. After initialization, all lookups are immutable and lock-free.

---

## Prerequisites & Building

### Prerequisites

- **Zig** (0.13.0 or later)
- **libcurl** runtime libraries (`libcurl4` on Debian/Ubuntu)

### Building

Build using the Zig build system or the included Makefile:

```bash
# Build the optimized shared library and test harness
make

# Or directly with Zig
zig build -Doptimize=ReleaseSmall
```

This generates:
- `bin/libsecrets_injector.so` (the preload library)
- `bin/test_app` (test verification binary)

### Cross-Compilation

Zig supports cross-compilation without external toolchains:

```bash
# Target Linux ARM64
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSmall
```

---

## Usage Examples

### Local Application

Run any binary locally with `LD_PRELOAD`:

```bash
SECRETS_VAULT_URL="https://vault.bitwarden.com/api/secrets" \
SECRETS_FETCH_KEY="0.your_token" \
LD_PRELOAD="./bin/libsecrets_injector.so" \
python3 -c 'import os; print("DB:", os.getenv("DATABASE_URL"))'
```

---

### OCI Container & Sidecar (Zero Image Changes)

The library is published as a minimal OCI container image to GitHub Container Registry:

```
ghcr.io/net-pilgrim/secrets-injector:latest
```

By providing the library via an OCI container image, **no modifications or rebuilds to your application Docker image are needed**. The container writes `libsecrets_injector.so` to a shared volume mounted between the injector and your application container.

The image supports two execution modes:
- **Copy & Exit (Init Container)**: Copies the library into the shared mount directory and terminates (`exit 0`).
- **Sidecar Mode**: Copies the library and remains running in standby mode (`sleep infinity`) for pods or platforms requiring active sidecars.

#### 1. Kubernetes (Init Container - Recommended)

Use an `initContainer` with a shared `emptyDir` volume. The injector mounts the shared volume at `/shared` (default) and immediately copies `libsecrets_injector.so` before your app starts:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      volumes:
        - name: injector-volume
          emptyDir: {}

      initContainers:
        - name: secrets-injector
          image: ghcr.io/net-pilgrim/secrets-injector:latest
          volumeMounts:
            - name: injector-volume
              mountPath: /shared

      containers:
        - name: app
          image: my-app:latest # Unmodified application image!
          env:
            - name: LD_PRELOAD
              value: /injector/libsecrets_injector.so
            - name: SECRETS_VAULT_URL
              value: "https://vault.bitwarden.com/api/secrets"
            - name: SECRETS_FETCH_KEY
              valueFrom:
                secretKeyRef:
                  name: vault-token
                  key: token
            # Optional injector settings:
            # - name: SECRETS_INJECTOR_DEBUG
            #   value: "1"
            # - name: SECRETS_INJECTOR_FAIL_FAST
            #   value: "1"
          volumeMounts:
            - name: injector-volume
              mountPath: /injector
              readOnly: true
```

#### 2. Kubernetes (Native Sidecar - K8s 1.28+)

For Kubernetes clusters with `SidecarContainers` enabled (default in K8s 1.28+), add `restartPolicy: Always` and pass `sidecar` as an argument:

```yaml
      initContainers:
        - name: secrets-injector
          image: ghcr.io/net-pilgrim/secrets-injector:latest
          restartPolicy: Always
          args: ["sidecar"]
          volumeMounts:
            - name: injector-volume
              mountPath: /shared
```

#### 3. Docker Compose

In Docker Compose, use a named volume and wait for the injector service to complete:

```yaml
services:
  secrets-injector:
    image: ghcr.io/net-pilgrim/secrets-injector:latest
    volumes:
      - injector-volume:/shared

  my-app:
    image: my-company/my-app:latest
    depends_on:
      secrets-injector:
        condition: service_completed_successfully
    volumes:
      - injector-volume:/injector:ro
    environment:
      - LD_PRELOAD=/injector/libsecrets_injector.so
      - SECRETS_VAULT_URL=https://vault.internal/secrets
      - SECRETS_FETCH_KEY=${VAULT_TOKEN}

volumes:
  injector-volume:
```

#### 4. Standalone Docker CLI

Share the library using a named Docker volume:

```bash
# 1. Create a volume and copy the library into it
docker volume create injector-volume
docker run --rm -v injector-volume:/shared ghcr.io/net-pilgrim/secrets-injector:latest

# 2. Run your application container with zero changes to its Dockerfile
docker run --rm \
  -v injector-volume:/injector:ro \
  -e LD_PRELOAD=/injector/libsecrets_injector.so \
  -e SECRETS_VAULT_URL="https://vault.bitwarden.com/api/secrets" \
  -e SECRETS_FETCH_KEY="0.your_access_token..." \
  python:3.11-slim python3 -c 'import os; print("Injected secret:", os.getenv("API_KEY"))'
```

---

### Embedding into Application Dockerfile

If you prefer building the library directly into your container image rather than mounting via a sidecar/init volume:

```dockerfile
# Copy prebuilt library or from builder stage
COPY bin/libsecrets_injector.so /usr/local/lib/libsecrets_injector.so
ENV LD_PRELOAD=/usr/local/lib/libsecrets_injector.so

CMD ["./my_server_binary"]
```

---

## Testing

The project includes both native Zig unit tests and an automated integration test suite:

```bash
# Run unit tests (testing all JSON, Vault v2, Bitwarden, 1Password, and Dotenv schemas)
make test-unit

# Run full integration test suite against a live mock web vault
make test

# Build local Docker image
make docker-build
```

### Integration Test Suite Verification

The integration test suite validates:
1. Native C binary `getenv` & `secure_getenv` secret resolution.
2. Python `os.getenv` and `os.environ` injection.
3. HashiCorp Vault KV v2 structure parsing (`data.data`).
4. Plain text / dotenv format parsing.
5. Clean passthrough when `SECRETS_FETCH_KEY` is not set.
6. Graceful error handling on invalid authentication keys.
7. `FAIL_FAST=1` abort behavior.
8. Bitwarden Secrets Manager API format resolution.
9. 1Password Connect API format resolution.

---

## Project Structure

```
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI for tests & GHCR OCI image publishing
├── Dockerfile              # Multi-stage OCI container build
├── docker-entrypoint.sh    # Entrypoint supporting init & sidecar standby modes
├── build.zig               # Zig build script
├── Makefile                # Convenient build, test & docker targets
├── README.md               # Documentation
├── src/
│   ├── injector.zig        # LD_PRELOAD hooks, memory scrubbing, C ABI exports
│   ├── json_parser.zig     # Schema parser for Bitwarden, 1Password, Vault, and Dotenv
│   └── vault_client.zig    # libcurl HTTP client and authentication handler
└── test/
    ├── run_tests.sh        # Integration test runner
    ├── test_app.c          # Verification test application
    └── vault_server.py     # Multi-endpoint mock web vault server
```
