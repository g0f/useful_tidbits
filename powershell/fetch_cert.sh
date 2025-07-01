#!/bin/bash

#same thing as the powershell in heart but for linux

set -euo pipefail
set -x

VAULT_NAME="xx"
CERT_NAME="xx"
RENEW_THRESHOLD_DAYS=45

CERT_OUTPUT_PATH="/etc/ssl/certs/xx.crt"
KEY_OUTPUT_PATH="/etc/ssl/private/xx.key"
TEMP_PFX_PATH="/tmp/xx.pfx"

if [ ! -f "$CERT_OUTPUT_PATH" ]; then
  echo "Current certificate not found. Proceeding with download."
  CURRENT_EXPIRY_EPOCH=0
else
  CURRENT_EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_OUTPUT_PATH" | cut -d= -f2)
  CURRENT_EXPIRY_EPOCH=$(date -d "$CURRENT_EXPIRY_DATE" +%s)
fi

NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (CURRENT_EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
echo "Current certificate expires in $DAYS_LEFT days."

if [ "$DAYS_LEFT" -le "$RENEW_THRESHOLD_DAYS" ]; then
  echo "Renewing certificate..."

  az login --identity > /dev/null 2>&1

  az keyvault secret download \
    --vault-name "$VAULT_NAME" \
    --name "$CERT_NAME" \
    --file "$TEMP_PFX_PATH" \
    --encoding base64

  if [ $? -eq 0 ]; then
    echo "Certificate downloaded. Extracting..."

    openssl pkcs12 -in "$TEMP_PFX_PATH" -nocerts -nodes -out "$KEY_OUTPUT_PATH" -passin pass:
    if [ $? -eq 0 ]; then
      echo "Private key extracted to $KEY_OUTPUT_PATH"
      chmod 600 "$KEY_OUTPUT_PATH"
    else
      echo "Error: Failed to extract private key"
      exit 1
    fi

    openssl pkcs12 -in "$TEMP_PFX_PATH" -clcerts -nokeys -out "$CERT_OUTPUT_PATH" -passin pass:
    if [ $? -eq 0 ]; then
      echo "Certificate extracted to $CERT_OUTPUT_PATH"
      chmod 644 "$CERT_OUTPUT_PATH"
    else
      echo "Error: Failed to extract certificate"
      exit 1
    fi
    rm -f "$TEMP_PFX_PATH"

    # Tests
    apache2ctl configtest
    if [ $? -eq 0 ]; then
      echo "Apache config OK. Reloading services..."
      sudo systemctl reload apache2 && echo "Apache reloaded."
    else
      echo "Error: Apache config test failed. Not reloading."
      exit 1
    fi

    echo "Certificate renewal completed successfully!"
  else
    echo "Error: Failed to download certificate from Key Vault"
    exit 1
  fi
else
  echo "Certificate is valid for more than $RENEW_THRESHOLD_DAYS days. No action taken."
fi

