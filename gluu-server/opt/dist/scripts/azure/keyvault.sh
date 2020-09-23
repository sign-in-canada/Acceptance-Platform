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

# Obtain an access token
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true | extractJSONValue access_token)

# Verify connectivity before going any further
if fetchSecret 'x' > /dev/null 2>&1 ; then
   echo "Connected to Keyvault ${KEYVAULT}"
else
   echo "Connection to Keyvault ${KEYVAULT} failed. Aborting."
   exit 1
fi

# Create a ramfs directory to hold the secrets
umask 227
mkdir $KV_DIR
mount -t ramfs ramfs $KV_DIR
mkdir ${KV_DIR}/certs ${KV_DIR}/secrets

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

# Get the encrption key for MFA
fetchSecret MFAKey > ${KV_DIR}/secrets/MFAKey

# Get the API key for notify
fetchSecret NotifyKey > ${KV_DIR}/secrets/NotifyKey

# Get the "salt"
salt=$(fetchSecret APsalt)
if [ "$salt" != "undefined" ] ; then
   echo "encodeSalt = $salt" > ${KV_DIR}/secrets/salt
   ln -s -f ${KV_DIR}/secrets/salt /etc/gluu/conf/salt

   # Get the Couchbase admin password
   GCB="/etc/gluu/conf/gluu-couchbase.properties"
   if [ -f $GCB ]; then
      # First time. Strip out the password to create a template
      sed '/^auth.userPassword:/d' $GCB > ${GCB}.template
   fi
   cp ${GCB}.template ${KV_DIR}/secrets/gluu-couchbase.properties
   echo "auth.userPassword:" $(fetchSecret APGluuPW) \
      >> ${KV_DIR}/secrets/gluu-couchbase.properties
   ln -s -f ${KV_DIR}/secrets/gluu-couchbase.properties $GCB

   # Get the Couchbase shibboleth password
   echo "idp.attribute.resolver.datasource.password=" \
      $(fetchSecret APShibPW) > ${KV_DIR}/secrets/secrets.properties
   ln -s -f ${KV_DIR}/secrets/secrets.properties /opt/shibboleth-idp/conf/secrets.properties
fi

exit 0
