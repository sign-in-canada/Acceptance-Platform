#/bin/bash

umask 0
source install.params
read -p "Please enter the configuration decryption passaword => " -e -s PASSWORD

rm -f ${1}*

echo Downloading ${1}...
wget ${STAGING_URL}/${1}.tgz
wget ${STAGING_URL}/${1}.tgz.sha
echo -n "Checking download integrity..."
if [ "$(cut -d ' ' -f 2 ${1}.tgz.sha)" = "$(openssl sha256 ${1}.tgz | cut -d ' ' -f 2)" ] ; then
   echo "Passed."
else
   echo "Failed!. Aborting installation."
   exit 1
fi

echo "Re-installing Gluu"
yum remove -y gluu-server
rm -rf /opt/gluu-server*
yum localinstall -y ./gluu-server-4.1.0-centos7.x86_64.rpm

echo "Adding Sign In Canada customizations..."
tar xvzf ${1}.tgz -C /opt/gluu-server/

echo "Configuring Keyvault URL..."
echo "KEYVAULT=${KEYVAULT_URL}" > /opt/gluu-server/etc/default/azure

echo "Configuring SAML metadata URL..."
sed -i "s|\[URL\]|${METADATA_URL}|g" \
   /opt/gluu-server/opt/dist/signincanada/shibboleth-idp/conf/metadata-providers.xml

echo "Configuring Gluu..."
cp setup.properties.last.enc /opt/gluu-server/install/community-edition-setup/setup.properties.enc
ssh  -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost \
   "/install/community-edition-setup/setup.py -n -f /install/community-edition-setup/setup.properties.enc -properties-password $PASSWORD ; \
    /opt/dist/signincanada/postinstall.sh"

echo "Restarting..."
/sbin/gluu-serverd restart

echo "${1} has been installed."
