#!/bin/bash
#
# Extract the oxAuth OpenID private keys to PEM format for use by Passport
#

# Retrieve the key ids (kid) for each key from the oxAuth jwks_uri
kids=$(curl -s https://$(hostname)/oxauth/restv1/jwks | jq -r ".keys[].kid")

# Cleanup old keys
rm -rf /run/keyvault/keys
umask 227
mkdir /run/keyvault/keys

# Retrieve the oxAuth keystore password
export gluuPW=$(/opt/gluu/bin/encode.py -d $(grep auth.userPassword /etc/gluu/conf/gluu-couchbase.properties | awk -F': ' '{print $2}'))
keyStoreSecret=$(openssl enc -d -aes-256-cbc -pass env:gluuPW -in /install/community-edition-setup/setup.properties.last.enc |
                 grep oxauth_openid_jks_pass | awk -F'=' '{print $2}')

# Use the salt to encrypt the keys
export encodeSalt=$(awk -F'= ' '{print $2}' /etc/gluu/conf/salt)

for kid in $kids ; do
    echo "Extracting $kid"
    # Extract the individual key
    /opt/jre/bin/keytool -importkeystore -srckeystore /etc/certs/oxauth-keys.jks -destkeystore /run/keyvault/keys/${kid}.p12 -alias ${kid} -srcstorepass $keyStoreSecret -deststorepass $keyStoreSecret
    # Convert the private key to AES-encrypted PKCS8
    openssl pkcs12 -in /run/keyvault/keys/${kid}.p12 -nocerts -passin pass:${keyStoreSecret} -nodes -nocerts |
        openssl pkcs8  -topk8 -v2 aes256 -out /run/keyvault/keys/${kid}.pem -passout env:encodeSalt
    rm /run/keyvault/keys/${kid}.p12
done
