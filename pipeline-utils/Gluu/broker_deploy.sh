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

echo "Configuring Gluu for ${environment_name} environment..."
export GLUU_PASSWORD=$(aws ssm get-parameter --name "/SIC/${environment_name}/GLUU_PASSWORD" --with-decryption | jq -r '.Parameter.Value')
ip_addr=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document |jq -r '.privateIp')
aws s3 cp "s3://sic-${environment_lower}-env-config-store/setup.properties.last.enc" - |
   openssl enc -d -aes-256-cbc -pass env:GLUU_PASSWORD |
   sed -e "2i ip=${ip_addr}" |
   openssl enc -aes-256-cbc -pass env:GLUU_PASSWORD -out /opt/gluu-server/install/community-edition-setup/setup.properties.enc

ssh  -t -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost <<-EOF
   /install/community-edition-setup/setup.py -cnf /install/community-edition-setup/setup.properties.enc -properties-password '$GLUU_PASSWORD' --import-ldif=/opt/dist/signincanada/ldif
   /opt/dist/signincanada/postinstall.sh
EOF

echo "Starting Gluu..."
/sbin/gluu-serverd restart
