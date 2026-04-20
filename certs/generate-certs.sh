#!/usr/bin/env bash
set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
umask 077

DAYS_CA=3650
DAYS_SVC=365

CA_KEY="${OUT}/ca-key.pem"
CA_CERT="${OUT}/ca.pem"
CA_SUBJ="/C=RU/ST=RT/L=Kazan/O=KFU/OU=IVMiIT/CN=authz-dev-ca"

SERVICES=("orders" "payments" "policy-server")

mkdir -p "${OUT}"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
  echo "[*] Генерация CA..."
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${DAYS_CA}" \
    -subj "${CA_SUBJ}" -out "${CA_CERT}"
fi

gen_service() {
  local name="$1"
  local key="${OUT}/${name}-key.pem"
  local csr="${OUT}/${name}.csr"
  local cert="${OUT}/${name}.pem"
  local ext="${OUT}/${name}.ext"

  openssl genrsa -out "${key}" 2048
  openssl req -new -key "${key}" \
    -subj "/C=RU/ST=RT/L=Kazan/O=KFU/OU=IVMiIT/CN=${name}" \
    -out "${csr}"

  cat > "${ext}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${name}
DNS.2 = ${name}.local
EOF

  openssl x509 -req -in "${csr}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${cert}" -days "${DAYS_SVC}" -sha256 -extfile "${ext}"

  rm -f "${csr}" "${ext}"
}

for s in "${SERVICES[@]}"; do
  [[ -f "${OUT}/${s}.pem" && -f "${OUT}/${s}-key.pem" ]] || gen_service "${s}"
done

echo "[+] Certificates готовы в ${OUT}"
