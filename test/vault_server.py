#!/usr/bin/env python3
import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
EXPECTED_TOKEN = sys.argv[2] if len(sys.argv) > 2 else "test-secret-vault-key-42"

class VaultHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("[vault_server] %s - %s\n" % (self.address_string(), format % args))

    def check_auth(self):
        vault_token = self.headers.get("X-Vault-Token")
        auth_header = self.headers.get("Authorization")
        bearer_token = None
        if auth_header and auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip()

        token = vault_token or bearer_token
        return token == EXPECTED_TOKEN

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if not self.check_auth():
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden: invalid fetch key"}).encode("utf-8"))
            return

        if self.path in ("/secrets", "/v1/secrets"):
            secrets = {
                "DATABASE_URL": "postgresql://dbuser:supersecretpass@db.internal:5432/production",
                "API_KEY": "sk_live_9876543210abcdef",
                "JWT_SECRET": "my-ultra-secure-jwt-signing-key",
                "FEATURE_FLAG_ENABLED": "true"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(secrets).encode("utf-8"))
            return

        if self.path == "/vault_kv2":
            secrets = {
                "data": {
                    "data": {
                        "KV2_SECRET": "hashicorp_vault_v2_value",
                        "APP_ENVIRONMENT": "production-vault"
                    },
                    "metadata": {"version": 2}
                }
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(secrets).encode("utf-8"))
            return

        if self.path == "/bitwarden/secrets":
            bw_response = {
                "data": [
                    {
                        "id": "73e97022-b5e0-49ec-85d9-4fa2210ffbe9",
                        "organizationId": "00000000-0000-0000-0000-000000000000",
                        "key": "BW_DATABASE_URL",
                        "value": "postgres://bwuser:secret@localhost:5432/bwdb",
                        "note": "Bitwarden managed DB"
                    },
                    {
                        "id": "84a12345-0000-0000-0000-000000000000",
                        "key": "BW_API_KEY",
                        "value": "bw_live_token_xyz999"
                    }
                ],
                "continuationToken": None
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(bw_response).encode("utf-8"))
            return

        if self.path.startswith("/1password"):
            op_response = {
                "id": "item-abc-123",
                "title": "Production Web App",
                "vault": {"id": "vault-xyz"},
                "category": "SERVER",
                "fields": [
                    {
                        "id": "username",
                        "type": "STRING",
                        "label": "OP_USER",
                        "value": "ops_admin"
                    },
                    {
                        "id": "password",
                        "type": "CONCEALED",
                        "label": "OP_PASSWORD",
                        "value": "op_ultra_secret_pass"
                    },
                    {
                        "id": "api_token",
                        "type": "CONCEALED",
                        "label": "OP_API_TOKEN",
                        "value": "ops_token_abc123"
                    }
                ]
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(op_response).encode("utf-8"))
            return

        if self.path == "/dotenv":
            dotenv_data = "DOTENV_SECRET=secret_from_dotenv_format\nDOTENV_PORT=9000\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(dotenv_data.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

def run():
    server = HTTPServer(("127.0.0.1", PORT), VaultHandler)
    sys.stderr.write(f"[vault_server] Listening on http://127.0.0.1:{PORT} (Token: {EXPECTED_TOKEN})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    run()
