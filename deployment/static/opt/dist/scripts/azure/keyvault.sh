#!/bin/sh
#
# Fetch certificates, keys and secrets from Azure KeyVault
#
# Arguments:
#
# keyvault.sh [KeyVault URI]

KEYVAULT=$1
API_VER='7.0'

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

fetchKey () {
   curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/secrets/${1}?api-version=${API_VER} \
      | extractJSONValue value | base64 --decode \
      | openssl pkcs12 -passin 'pass:' -nodes -nocerts \
      | openssl rsa -outform PEM
}

# Obtain an access token
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true | extractJSONValue access_token)

# Create a tmpfs directory to store the secrets
mkdir -p -m 551 /run/certs
chown root:gluu /run/certs
cd /run/certs

# Get the certificates and their private keys
CERTS=$(curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/certificates?api-version=${API_VER} \
   | /opt/node/bin/node -e \
    "let certs = JSON.parse(require('fs').readFileSync(0, 'utf8')).value; \
     for (cert of certs) { \
        console.log(cert.id.split('/').pop()); \
     }" )

umask 337
for cert in $CERTS ; do
   fetchCert $cert > ${cert}.crt
   fetchKey $cert > ${cert}.key
   chown root:gluu *.crt *.key
   ln -s -f /run/certs/${cert}.crt /etc/certs/${cert}.crt && chown root:gluu /etc/certs/${cert}.crt
   ln -s -f /run/certs//${cert}.key /etc/certs/${cert}.key && chown root:gluu /etc/certs/${cert}.key
done

exit 0
