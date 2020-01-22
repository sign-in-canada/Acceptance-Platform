#!/bin/bash
#
# Fetch certificates, keys and secrets from Azure KeyVault
#
# Arguments:
#
# keyvault.sh [KeyVault URI]

KEYVAULT=$1
API_VER='7.0'
KV_DIR=/run/keyvault

extractJSONValue () {
   /opt/node/bin/node -e "console.log(JSON.parse(require('fs').readFileSync(0, 'utf8'))[process.argv[1]])" $1
}

fetchSecret () {
   curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/secrets/${1}?api-version=${API_VER} \
      | extractJSONValue value
}

# Create a ramfs directory to hold the secrets
umask 227
mkdir $KV_DIR
mount -t ramfs ramfs $KV_DIR
mkdir ${KV_DIR}/certs ${KV_DIR}/secrets

# Obtain an access token
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true | extractJSONValue access_token)

# Get the certificates and their private keys
certs=$(curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/certificates?api-version=${API_VER} \
   | /opt/node/bin/node -e \
    "let certs = JSON.parse(require('fs').readFileSync(0, 'utf8')).value; \
     for (cert of certs) { \
        console.log(cert.id.split('/').pop()); \
     }" )

for cert in $certs ; do
   fetchSecret $cert | tee \
      >(openssl x509 -outform pem  > ${KV_DIR}/certs/${cert}.crt) \
      >(openssl rsa -outform PEM > ${KV_DIR}/certs/${cert}.key) \
      >(sed '1,/-----END CERTIFICATE-----/d' > ${KV_DIR}/certs/${cert}.chain) \
      > /dev/null
   ln -s -f ${KV_DIR}/certs/${cert}.crt /etc/certs/${cert}.crt
   ln -s -f ${KV_DIR}/certs/${cert}.chain /etc/certs/${cert}.chain
   ln -s -f ${KV_DIR}/certs/${cert}.key /etc/certs/${cert}.key
done

# Get the Application Insights Instrumentation Key
fetchSecret InstrumentationKey > ${KV_DIR}/secrets/InstrumentationKey

# TODO: Get the Couchbase password

exit 0
