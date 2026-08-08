#!/bin/sh

set -eu

output_directory=${1:-certs}
certificate_file="$output_directory/server.pem"
private_key_file="$output_directory/server-key.pem"

if ! command -v openssl >/dev/null 2>&1; then
	echo "error: openssl is required" >&2
	exit 1
fi

if [ -e "$certificate_file" ] || [ -e "$private_key_file" ]; then
	echo "error: certificate or key already exists in $output_directory" >&2
	echo "remove both files before generating a replacement" >&2
	exit 1
fi

mkdir -p "$output_directory"

openssl req \
	-x509 \
	-newkey rsa:2048 \
	-sha256 \
	-nodes \
	-days 365 \
	-keyout "$private_key_file" \
	-out "$certificate_file" \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
	-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
	-addext "extendedKeyUsage=serverAuth"

chmod 600 "$private_key_file"
chmod 644 "$certificate_file"

echo "created $certificate_file"
echo "created $private_key_file"
echo "start the server with: go run . -cert $certificate_file -key $private_key_file"
