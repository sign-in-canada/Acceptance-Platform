#!/bin/bash
#
# Fetch certificates, keys and secrets from Azure KeyVault
#
# Arguments:
#
# keyvault.sh [KeyVault URI]

KEYVAULT=$1
API_VER='7.1'
KV_DIR=/run/keyvault

# Obtain keyvault access token
for retries in {1..10} ; do
   token_json=$(curl -s --retry 5 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true)
   curl_rc=$?
   if [[ $curl_rc -ne 0 || -z "$token_json" || "$token_json" =~ "error" ]] ; then
      echo "Failed to obtain an access token from the metadata service during attempt #${retries} with curl error code $curl_rc" >&2
      echo "Response content was: $token_json" >&2
      sleep 10
   else
      break
   fi
done

if (( retries >= 10 )) ; then # Error
   echo "Giving up." >&2
   exit 1
else
   access_token=$(echo -n ${token_json} | jq -r '.access_token')
fi

listCertificates () {
   for retries in {1..10} ; do
      json=$(curl -s --retry 5 -H "Authorization: Bearer ${access_token}" "${KEYVAULT}/certificates?api-version=${API_VER}")
      curl_rc=$?
      if [[ $curl_rc -ne 0 || -z "$json" || "$json" =~ "error" ]] ; then
         echo "Faliled to obtain certificate list from keyvault during attempt #${retries} with curl error code $curl_rc" >&2
         echo "Response content was: $json" >&2
         sleep 10
      else
         break
      fi
   done

   if (( retries >= 10 )) ; then # Error
   echo "Giving up." >&2
      exit 1
   else
      echo -n ${json} | jq -r '.value[] | .id | split("/")[-1]'
   fi
}

fetchSecret () {
   for retries in {1..10} ; do
      json=$(curl -s --retry 5 -H "Authorization: Bearer ${access_token}" "${KEYVAULT}/secrets/${1}?api-version=${API_VER}")
      curl_rc=$?
      if [[ $curl_rc -ne 0 || -z "$json" || "$json" =~ "error" ]] ; then
         echo "Faliled to obtain secret ${1} from keyvault during attempt #${retries} with curl error code $curl_rc" >&2
         echo "Response content was: $json" >&2
         sleep 10
      else
         break
      fi
   done
   
   if (( retries >= 10 )) ; then # Error
      echo "Giving up." >&2
      exit 1
   else
      echo -n ${json} | jq -r '.value'
   fi
}

# Create a ramfs directory to hold the secrets
umask 227
mkdir $KV_DIR
mount -t ramfs ramfs $KV_DIR
mkdir ${KV_DIR}/certs ${KV_DIR}/secrets

# Get the certificates and their private keys
certs=$(listCertificates)

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

   if [ -d /opt/shibboleth-idp/conf ] ; then
      # Get the Couchbase shibboleth password
      echo "idp.attribute.resolver.datasource.password=" \
         $(fetchSecret APShibPW) > ${KV_DIR}/secrets/secrets.properties
      ln -s -f ${KV_DIR}/secrets/secrets.properties /opt/shibboleth-idp/conf/secrets.properties
   fi
fi

exit 0
