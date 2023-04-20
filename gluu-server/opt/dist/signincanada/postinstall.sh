#!/bin/sh

environment_name=$(curl -s curl http://169.254.169.254/latest/meta-data/tags/instance/Environment)
environment_lower=$(echo "$environment_name" | tr '[:upper:]' '[:lower:]')

# Obtain the Gluu admin password and salt from parameter store
export GLUU_PASSWORD=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
export GLUU_SALT=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_SALT" --with-decryption | jq -r '.Parameter.Value')

echo 'Enabling logstash...'
systemctl enable logstash

echo 'Enabling the couchbase health check service...'
systemctl enable cbcheck

umask 27
newgrp gluu

echo 'Retreiving Gluu Config file...'
aws s3 cp "s3://sic-${environment_lower}-env-config-store/setup.properties.last.enc" /install/community-edition-setup/setup.properties.last.enc
echo 'Restoring oxAuth keystore...'
aws s3 cp "s3://sic-${environment_lower}-env-config-store/oxauth-keys.pkcs12" /etc/certs/oxauth-keys.pkcs12

echo "Intalling passport UMA RS and RP keystores..."
aws s3 cp "s3://sic-${environment_lower}-env-config-store/passport-rs.jks" /etc/certs/passport-rs.jks
aws s3 cp "s3://sic-${environment_lower}-env-config-store/passport-rp.jks" /etc/certs/passport-rp.jks
passport_rp_client_jks_pass=$(openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD -in /install/community-edition-setup/setup.properties.last.enc |
                              grep '^passport_rp_client_jks_pass=' |
                              awk -F'=' '{print $2}')
passport_rp_client_cert_alias=$(openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD -in /install/community-edition-setup/setup.properties.last.enc |
                              grep '^passport_rp_client_cert_alias=' |
                              awk -F'=' '{print $2}')
/opt/jre/bin/keytool -importkeystore -srckeystore /etc/certs/passport-rp.jks -srcstoretype jks -srcstorepass ${passport_rp_client_jks_pass} \
                     -destkeystore /etc/certs/passport-rp.pkcs12 -deststorepass ${passport_rp_client_jks_pass} -alias ${passport_rp_client_cert_alias}
openssl pkcs12 -in /etc/certs/passport-rp.pkcs12 -nocerts -passin pass:${passport_rp_client_jks_pass} -nodes -nocerts |
        openssl rsa -out /etc/certs/passport-rp.pem
rm /etc/certs/passport-rp.pkcs12

echo "Intalling passport SAML Keys..."
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_CRT" | jq -r '.Parameter.Value' > /etc/certs/passport-sp.crt
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_KEY" --with-decryption | jq -r '.Parameter.Value' > /etc/certs/passport-sp.key
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_ENC_CRT" | jq -r '.Parameter.Value' > /etc/certs/passport-sp-enc.crt
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_ENC_KEY" --with-decryption | jq -r '.Parameter.Value' > /etc/certs/passport-sp-enc.key

echo "Extracting oxAuth keys for use by passport"
oxauth_openid_jks_pass=$(openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD -in /install/community-edition-setup/setup.properties.last.enc |
                              grep '^oxauth_openid_jks_pass=' |
                              awk -F'=' '{print $2}')
keys=$(/opt/jre/bin/keytool -list -keystore /etc/certs/oxauth-keys.pkcs12 -storetype pkcs12 -storepass ${oxauth_openid_jks_pass} | grep 'PrivateKeyEntry' | cut -d, -f1)
for keyId in ${keys} ; do
    echo "Extracting $keyId"
    # Extract the individual key
    /opt/jre/bin/keytool -importkeystore -srckeystore /etc/certs/oxauth-keys.pkcs12 -srcstoretype pkcs12 \
                         -destkeystore /etc/certs/${keyId}.p12 -alias ${keyId} \
                         -srcstorepass $oxauth_openid_jks_pass -deststorepass $oxauth_openid_jks_pass
    # Convert the private key to AES-encrypted PKCS8
    openssl pkcs12 -in /etc/certs/${keyId}.p12 -nocerts -passin pass:${oxauth_openid_jks_pass} -nodes -nocerts |
        openssl pkcs8  -topk8 -v2 aes256 -out /etc/certs/${keyId}.pem -passout env:GLUU_SALT
    rm /etc/certs/${keyId}.p12
done

umask 22
echo 'Installing the Custom UI and dependencies...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo 'Installing the Notify service...'
mkdir -p /opt/gluu/node/gc/notify/logs
tar xzf /opt/dist/signincanada/node-services.tgz -C /opt/gluu/node/gc/notify
chown -R node:node /opt/gluu/node/gc
cp /opt/dist/signincanada/notify-config.json /etc/gluu/conf
systemctl enable notify

echo 'Removing unused Gluu authentication pages...'
zip -d -q /opt/gluu/jetty/oxauth/webapps/oxauth.war "/auth/*"
chown jetty:gluu /opt/gluu/jetty/oxauth/webapps/oxauth.war

if [ -d /opt/shibboleth-idp/conf ] ; then
   echo 'Configuring Shibboleth...'
   install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_SIGNING_CRT" | jq -r '.Parameter.Value' > /etc/certs/idp-signing.crt
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_SIGNING_KEY" --with-decryption | jq -r '.Parameter.Value' > /etc/certs/idp-signing.key
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_ENCRYPTION_CRT" | jq -r '.Parameter.Value' > /etc/certs/idp-encryption.crt
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_ENCRYPTION_KEY" --with-decryption | jq -r '.Parameter.Value' > /etc/certs/idp-encryption.key
fi
if [ -d /opt/gluu/jetty/idp ] ; then
   echo 'Installing the Application Insights SDK into Shibboleth...'
   install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/gluu/jetty/oxauth/custom/libs/applicationinsights-core-*.jar /opt/gluu/jetty/idp/custom/libs
fi

echo "Configuring Couchbase scan consistency"
sed -i 's/not_bounded/request_plus/g' /etc/gluu/conf/gluu-couchbase.properties

echo "Patching oxTrust log4j config"
mkdir -p /tmp/warpatch
pushd /tmp/warpatch
/opt/jre/bin/jar -x -f /opt/gluu/jetty/identity/webapps/identity.war WEB-INF/classes/log4j2.xml
sed -i "s/DEBUG/INFO/g" WEB-INF/classes/log4j2.xml
/opt/jre/bin/jar -u -f /opt/gluu/jetty/identity/webapps/identity.war WEB-INF/classes/log4j2.xml
popd
rm -rf /tmp/warpatch

echo "Patching FIDO2 API server"
mkdir -p /tmp/warpatch
pushd /tmp/warpatch
/opt/jre/bin/jar -x -f /opt/dist/signincanada/fido2-patch.war
/opt/jre/bin/jar -u -f /opt/gluu/jetty/fido2/webapps/fido2.war WEB-INF/classes/*
popd
rm -rf /tmp/warpatch

echo "Updating packages..."
yum update -y
echo 'Done.'
