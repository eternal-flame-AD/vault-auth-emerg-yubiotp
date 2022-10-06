#!/usr/bin/env bash

if [ -f ".env" ]; then
  . .env
fi

GOOS=linux go build

docker kill vaultplg 2>/dev/null || true
docker run --rm -d -p8208:8204 --name vaultplg  -v $(pwd):/emerg-yubiotp --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG=
{
  "backend": {"file": {"path": "/vault/data"}},
  "listener": [{"tcp": {"address": "0.0.0.0:8204", "tls_disable": true}}],
  "plugin_directory": "/emerg-yubiotp",
  "log_level": "debug",
  "disable_mlock": true,
  "api_addr": "http://localhost:8204",
  "ui": true
}
' vault server

sleep 2

export VAULT_ADDR=http://localhost:8208

initoutput=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
vault operator unseal $(echo "$initoutput" | jq -r .unseal_keys_hex[0])

export VAULT_TOKEN=$(echo "$initoutput" | jq -r .root_token)

vault write sys/plugins/catalog/auth/vault-auth-emerg-yubiotp \
    sha_256=$(sha256sum vault-auth-emerg-yubiotp | cut -d' ' -f1) \
    command="vault-auth-emerg-yubiotp"

vault auth enable \
    -path="emerg-yubiotp" \
    -plugin-name="vault-auth-emerg-yubiotp" plugin

vault write auth/emerg-yubiotp/config \
    yubiauth_client_id=$YUBIAUTH_CLIENT_ID \
    yubiauth_client_key=$YUBIAUTH_CLIENT_KEY \
    "delay=5" \
    allowed_keys=emerg-key-1

vault write sys/auth/emerg-yubiotp/tune listing_visibility="unauth"

echo "Issue an OTP now, this should fail"
read otp
VAULT_TOKEN=  vault write auth/emerg-yubiotp/login otp_response="$otp"

echo "Programming the key now"

vault write auth/emerg-yubiotp/key/emerg-key-1 \
    alias=emerg-person \
    public_id=$(echo "$otp" | cut -b -12) \
    delay=60

echo "Issue an OTP now, timer should trigger"
read otp
VAULT_TOKEN=  vault write auth/emerg-yubiotp/login otp_response="$otp"

vault write auth/emerg-yubiotp/key/emerg-key-1 next_eligible_time=1

echo "Issue an OTP now, this should succeed"
read otp
VAULT_TOKEN=  vault write auth/emerg-yubiotp/login otp_response="$otp"

bash