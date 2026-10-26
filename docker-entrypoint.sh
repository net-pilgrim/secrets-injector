#!/bin/sh
set -e

# Default destination directory
TARGET_DIR="${TARGET_DIR:-/shared}"

copy_injector() {
  dest="$1"
  mkdir -p "$dest" "$dest/glibc" "$dest/musl"
  
  # Default shared library (glibc-compatible)
  cp -f /usr/local/lib/libsecrets_injector.so "$dest/libsecrets_injector.so"
  
  # Explicit GLIBC flavour
  if [ -f /usr/local/lib/libsecrets_injector_glibc.so ]; then
    cp -f /usr/local/lib/libsecrets_injector_glibc.so "$dest/libsecrets_injector-glibc.so"
    cp -f /usr/local/lib/libsecrets_injector_glibc.so "$dest/glibc/libsecrets_injector.so"
  fi
  
  # Explicit MUSL flavour (for Alpine Linux workloads)
  if [ -f /usr/local/lib/libsecrets_injector_musl.so ]; then
    cp -f /usr/local/lib/libsecrets_injector_musl.so "$dest/libsecrets_injector-musl.so"
    cp -f /usr/local/lib/libsecrets_injector_musl.so "$dest/musl/libsecrets_injector.so"
  fi

  echo "[secrets-injector] Successfully installed secrets injector libraries to $dest/"
  echo "  - Glibc / Universal: $dest/libsecrets_injector.so (or libsecrets_injector-glibc.so)"
  echo "  - Musl / Alpine:     $dest/libsecrets_injector-musl.so"
}

case "$1" in
  sidecar)
    copy_injector "$TARGET_DIR"
    echo "[secrets-injector] Sidecar standby mode active. Keeping container alive..."
    exec sleep infinity
    ;;
  copy|"")
    copy_injector "$TARGET_DIR"
    if [ "${SIDECAR:-false}" = "true" ]; then
      echo "[secrets-injector] SIDECAR=true detected. Keeping container alive..."
      exec sleep infinity
    fi
    echo "[secrets-injector] Injection initialization complete."
    exit 0
    ;;
  *)
    # If the argument is a directory or path, copy there
    if [ -d "$1" ] || [ ! -x "$(command -v "$1" 2>/dev/null)" ]; then
      copy_injector "$1"
      if [ "${SIDECAR:-false}" = "true" ] || [ "${2:-}" = "sidecar" ]; then
        echo "[secrets-injector] Sidecar standby mode active. Keeping container alive..."
        exec sleep infinity
      fi
      exit 0
    else
      # Execute custom command
      exec "$@"
    fi
    ;;
esac
