#!/bin/sh
echo 'Stopping services...'
/usr/bin/systemctl stop httpd
/usr/bin/systemctl stop oxauth
/usr/bin/systemctl stop identity
/usr/bin/systemctl stop idp
/usr/bin/systemctl stop passport

echo 'Enabling the keyvault service...'
/usr/bin/systemctl enable keyvault

echo 'Installing the UI...'
chgrp gluu /etc/gluu/select_page_content.json
/usr/bin/tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo 'Configuring Shibboleth...'
cp /opt/dist/signincanada/postinstall/opt/shibboleth-idp/conf/* /opt/shibboleth-idp/conf
chmod 444 /opt/shibboleth-idp/conf/attribute-filter.xml
chmod 444 /opt/shibboleth-idp/conf/attribute-resolver.xml
chmod 444 /opt/shibboleth-idp/conf/metadata-providers.xml
chmod 444 /opt/shibboleth-idp/conf/relying-party.xml
chmod 444 /opt/shibboleth-idp/conf/saml-nameid.xml

echo 'Done.'
echo
echo 'To complete configuration...'
echo '  1) edit the keyvault name in /etc/default/azure'
echo '  2) uncomment the chain certificate in /etc/httpd/conf.d/https_gluu.conf'
echo '  3) log out and restart the container'
echo '  4) assign the acr to the LoA2 authentication script'
echo '  5) Fix the names of the passport SAML encryption certs'
