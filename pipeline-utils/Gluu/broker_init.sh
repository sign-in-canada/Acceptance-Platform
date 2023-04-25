# Initializes a new Sign In Canada broker environment

umask 0
set -o pipefail

# Obtain the internal IP address
ip_addr=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document |jq -r '.privateIp')
if [ $? -ne 0 ] ; then
   echo "Failed to obtain IP address from the metadata service. Aborting!"
   exit 1
fi

# Obtain the environment name
environment_name=$(curl -s http://169.254.169.254/latest/meta-data/tags/instance/Environment)
if [ $? -ne 0 ] ; then
   echo "Failed to retreive Environment tag from the metadata service. Aborting!"
   exit 1
fi
environment_lower=$(echo "$environment_name" | tr '[:upper:]' '[:lower:]')

# Obtain the config properties from the parameter store
hostname=$(aws ssm get-parameter --name "/SIC/${environment_name}/PUBLIC_HOSTNAME" | jq -r '.Parameter.Value')
cb_hosts=$(aws ssm get-parameter --name "/SIC/${environment_name}/COUCHBASE_HOSTS" | jq -r '.Parameter.Value')
metadata_url=$(aws ssm get-parameter --name "/SIC/${environment_name}/SAML_METADATA_URL" | jq -r '.Parameter.Value')
log_workspace=$(aws ssm get-parameter --name "/SIC/${environment_name}/LOG_WORKSPACE_ID" | jq -r '.Parameter.Value')
salt=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_SALT" --with-decryption | jq -r '.Parameter.Value')
if [ $? -ne 0 ] ; then
   echo "No salt defined in the param store. A new salt will be created!"
fi

# Obtain the admin passwords from parameter store
export GLUU_PASSWORD=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
export CB_PASSWORD=$(aws ssm get-parameter --name "/SIC/${environment_name}/CB_GLUU_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
if [ -n "${metadata_url}" ] ; then # TODO: Let setup.py generate this instead
    shib_password=$(aws ssm get-parameter --name "/SIC/${environment_name}/SHIB_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
fi

# Generate a new setup properties file for setup.py
{
cat <<-EOF
	#$(date)
	hostname=$hostname
	ip=${ip_addr}
	persistence_type=couchbase
	cb_install=2
	wrends_install=0
	couchbase_hostname=${cb_hosts}
	couchebaseClusterAdmin=gluu
	cb_password=${CB_PASSWORD}
	isCouchbaseUserAdmin=True
	orgName=TBS-SCT
	city=Ottawa
	state=ON
	countryCode=CA
	admin_email=signin-authenticanada@tbs-sct.gc.ca
	oxtrust_admin_password=${GLUU_PASSWORD}
	installPassport=True
	installFido2=True
	$([ -n "${salt}" ] && echo "encode_salt=${salt}")
	$([ -n "${shib_password}" ] && echo "installSaml=True")
	$([ -n "${shib_password}" ] && echo "couchbaseShibUserPassword=${shib_password}")
EOF
} |
openssl enc -aes-256-cbc -pass env:GLUU_PASSWORD -out /opt/gluu-server/install/community-edition-setup/setup.properties.enc

# Run the Gluu setup.py installer. This:
# 1) initializes and loads the database
# 2) generates new cyryptographic keys
# 3) produces a fully-populated setup.properties.last.enc that can be used to spin up future cluster instances

echo "Patching Gluu setup..."
# Extend oxAuth key lifetime to 2 years
sed -i 's/key_expiration=2,/key_expiration=730,/' /opt/gluu-server/install/community-edition-setup/setup_app/installers/oxauth.py
# Don't display the password
sed -i 's/enc with password {1}/enc with password/' /opt/gluu-server/install/community-edition-setup/setup_app/utils/properties_utils.py
# Fix oxTrust certificate trust store
sed -i 's|/usr/java/latest/jre/lib/security/cacerts|%(default_trust_store_fn)s|' /opt/gluu-server/install/community-edition-setup/templates/oxtrust/oxtrust-config.json
sed -i 's|\"caCertsPassphrase\":\"\"|\"caCertsPassphrase\":\"%(defaultTrustStorePW)s\"|' /opt/gluu-server/install/community-edition-setup/templates/oxtrust/oxtrust-config.json
# Don't start anything
sed -i '/^\s*start_services()$/d' /opt/gluu-server/install/community-edition-setup/setup.py

echo "Initializing Gluu..."
ssh  -t -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost \
   "/install/community-edition-setup/setup.py -cnf /install/community-edition-setup/setup.properties.enc -properties-password '$GLUU_PASSWORD' --import-ldif=/opt/dist/signincanada/ldif"

echo "Extacting new Gluu Configuration..."
cp /opt/gluu-server/install/community-edition-setup/setup.properties.last.enc .

echo "Tweaking config for cluster member init..."
openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD -in setup.properties.last.enc |
    sed -e "/^loadData=True/s/.*/loadData=False/g;/^ip=/d" |
    openssl enc -aes-256-cbc -pass env:GLUU_PASSWORD -out setup.properties.last.new
if [ $? -ne 0 ] ; then
    echo "Could tweak config. Aborting!"
    exit 1
else
    mv --backup setup.properties.last.new setup.properties.last.enc
fi

if [ -z "${salt}" ] ; then
	echo "Backing up Gluu salt..."
	salt=$(openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD -in setup.properties.last.enc | grep encode_salt= | awk -F'=' '{print $2}')
	aws ssm put-parameter --name "/SIC/${environment_name}/GLUU_SALT" --value "${salt}" --type "SecureString" --overwrite
fi

echo "Backing up Gluu configuration..."
aws s3 cp setup.properties.last.enc "s3://sic-${environment_lower}-env-config-store/setup.properties.last.enc"

echo "Backing up Gluu keystores..."
aws s3 cp /opt/gluu-server/etc/certs/oxauth-keys.pkcs12 "s3://sic-${environment_lower}-env-config-store/oxauth-keys.pkcs12"
aws s3 cp /opt/gluu-server/etc/certs/passport-rs.jks "s3://sic-${environment_lower}-env-config-store/passport-rs.jks"
aws s3 cp /opt/gluu-server/etc/certs/passport-rp.jks "s3://sic-${environment_lower}-env-config-store/passport-rp.jks"
aws ssm put-parameter --name "/SIC/${environment_name}/PASSPORT_RP_PEM" --value "$(< /opt/gluu-server/etc/certs/passport-rp.pem)" --type "SecureString" --overwrite
# TODO: Figure out Shibboleth key store(s)
