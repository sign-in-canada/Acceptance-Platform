#!/bin/sh
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

fetchCert () {
   echo "-----BEGIN CERTIFICATE-----"
   curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/certificates/${1}?api-version=${API_VER} \
      | extractJSONValue cer \
      | fold -w 65
   echo "-----END CERTIFICATE-----"
}

fetchSecret () {
   curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/secrets/${1}?api-version=${API_VER} \
      | extractJSONValue value
}

fetchKey () {
   fetchSecret $1 \
      | base64 --decode \
      | openssl pkcs12 -passin 'pass:' -nodes -nocerts \
      | openssl rsa -outform PEM
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
   fetchCert $cert > ${KV_DIR}/certs/${cert}.crt
   fetchKey $cert > ${KV_DIR}/certs/${cert}.key
   ln -s -f ${KV_DIR}/certs/${cert}.crt /etc/certs/${cert}.crt
   ln -s -f ${KV_DIR}/certs/${cert}.key /etc/certs/${cert}.key
done

# Get the Application Insights Instrumentation Key
fetchSecret InstrumentationKey > ${KV_DIR}/secrets/InstrumentationKey

# TODO: Get the Couchbase password

exit 0
