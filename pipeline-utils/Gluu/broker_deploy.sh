# Installs the Sign In Canada customization package over an inititialized Gluu container

umask 0
set -o pipefail

# Obtain the environment name
environment_name=$(curl -s curl http://169.254.169.254/latest/meta-data/tags/instance/Environment)
if [ $? -ne 0 ] ; then
   echo "Failed to retreive Environment tag from the metadata service. Aborting!"
   exit 1
fi
environment_lower=$(echo "$environment_name" | tr '[:upper:]' '[:lower:]')

echo "Patching Gluu setup..."
# Don't display the password
sed -i 's/enc with password {1}/enc with password/' /opt/gluu-server/install/community-edition-setup/setup_app/utils/properties_utils.py
# Don't generate new oxAuth keys or render config templates
sed -i "61,66d;70,81d" /opt/gluu-server/install/community-edition-setup/setup_app/installers/oxauth.py
# Don't generate new passport UMA keys or render passport templates
sed -i "137,154d;176,177d;179,181d" /opt/gluu-server/install/community-edition-setup/setup_app/installers/passport.py
# Don't start anything
sed -i '/^\s*start_services()$/d' /opt/gluu-server/install/community-edition-setup/setup.py

echo "Configuring Gluu for ${environment_name} environment..."
export GLUU_PASSWORD=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
ip_addr=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document |jq -r '.privateIp')
aws s3 cp "s3://sic-${environment_lower}-env-config-store/setup.properties.last.enc" - |
   openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD |
   sed -e "2i ip=${ip_addr}" |
   openssl enc -aes-256-cbc -pass env:GLUU_PASSWORD -out /opt/gluu-server/install/community-edition-setup/setup.properties.enc

ssh  -t -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost \
   "/install/community-edition-setup/setup.py -cnf /install/community-edition-setup/setup.properties.enc -properties-password '$GLUU_PASSWORD' --import-ldif=/opt/dist/signincanada/ldif" 

echo 'Installing keystores and certificates...'
umask 27
# OxAuth keystore
aws s3 cp "s3://sic-${environment_lower}-env-config-store/oxauth-keys.pkcs12" /opt/gluu-server/etc/certs/oxauth-keys.pkcs12

# Passport UMA keys
aws s3 cp "s3://sic-${environment_lower}-env-config-store/passport-rs.jks" /opt/gluu-server/etc/certs/passport-rs.jks
aws s3 cp "s3://sic-${environment_lower}-env-config-store/passport-rp.jks" /opt/gluu-server/etc/certs/passport-rp.jks
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_RP_PEM" --with-decryption | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/passport-rp.pem
passport_rp_client_cert_alias=$(aws s3 cp "s3://sic-${environment_lower}-env-config-store/setup.properties.last.enc" - |
                                openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD |
                                grep '^passport_rp_client_cert_alias=' |
                                awk -F'=' '{print $2}')
sed -i "12c\ \ \ \ \"keyId\":\ \"${passport_rp_client_cert_alias}\"," /opt/gluu-server/etc/gluu/conf/passport-config.json

# Passport SAML certificates
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_CRT" | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/passport-sp.crt
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_KEY" --with-decryption | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/passport-sp.key
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_ENC_CRT" | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/passport-sp-enc.crt
aws ssm get-parameter --name "/SIC/${environment_name}/PASSPORT_SP_ENC_KEY" --with-decryption | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/passport-sp-enc.key

metadata_url=$(aws ssm get-parameter --name "/SIC/${environment_name}/SAML_METADATA_URL" | jq -r '.Parameter.Value')
if [ -n "${metadata_url}" ] ; then
   # Shibboleth IDP certificates
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_SIGNING_CRT" | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/idp-signing.crt
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_SIGNING_KEY" --with-decryption | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/idp-signing.key
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_ENCRYPTION_CRT" | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/idp-encryption.crt
   aws ssm get-parameter --name "/SIC/${environment_name}/IDP_ENCRYPTION_KEY" --with-decryption | jq -r '.Parameter.Value' > /opt/gluu-server/etc/certs/idp-encryption.key
fi

chgrp --reference /opt/gluu-server/etc/certs /opt/gluu-server/etc/certs/*

ssh  -t -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost \
   "/opt/dist/signincanada/postinstall.sh"

echo "Starting Gluu..."
/sbin/gluu-serverd restart
