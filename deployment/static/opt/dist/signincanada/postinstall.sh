#!/bin/sh
echo 'Stopping services...'
/usr/bin/systemctl stop httpd
/usr/bin/systemctl stop oxauth
/usr/bin/systemctl stop identity
/usr/bin/systemctl stop idp
/usr/bin/systemctl stop passport

echo 'Enabling the keyvault service...'
/usr/bin/systemctl enable keyvault

echo 'Patching Shibboleth and oxAuth...'
mkdir -p /tmp/SICPatch/WEB-INF/lib
pushd /tmp/SICPatch > /dev/null
cp /opt/dist/signincanada/*.jar WEB-INF/lib
/usr/bin/zip -d /opt/gluu/jetty/idp/webapps/idp.war WEB-INF/lib/shib-oxauth-authn3-4.0.Final.jar
/usr/bin/zip /opt/gluu/jetty/idp/webapps/idp.war WEB-INF/lib/shib-oxauth-authn3-4.0.sic1.jar
/usr/bin/zip /opt/gluu/jetty/idp/webapps/idp.war WEB-INF/lib/applicationinsights-web-auto-2.5.1.jar
chown jetty:jetty /opt/gluu/jetty/idp/webapps/idp.war
/usr/bin/zip /opt/gluu/jetty/oxauth/webapps/oxauth.war WEB-INF/lib/applicationinsights-web-auto-2.5.1.jar
popd > /dev/null
rm -rf /tmp/SICPatch

echo 'Installing the UI...'
chgrp gluu /etc/gluu/select_page_content.json
/usr/bin/tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo -n 'Configuring Shibboleth...'
cp -R /opt/dist/signincanada/shibboleth-idp/conf/* /opt/shibboleth-idp/conf
chmod 444 /opt/shibboleth-idp/conf/attribute-filter.xml
chmod 444 /opt/shibboleth-idp/conf/attribute-resolver.xml
chmod 444 /opt/shibboleth-idp/conf/metadata-providers.xml
chmod 444 /opt/shibboleth-idp/conf/relying-party.xml
chmod 444 /opt/shibboleth-idp/conf/saml-nameid.xml
chown jetty:jetty /opt/shibboleth-idp/conf/*.js
chmod 644 /opt/shibboleth-idp/conf/*.js

echo 'Done.'
echo
echo 'To complete configuration...'
echo '  1) edit the keyvault name in /etc/default/azure'
echo '  2) uncomment the chain certificate in /etc/httpd/conf.d/https_gluu.conf'
echo '  3) log out and restart the container'
echo '  4) assign the acr to the LoA2 authentication script'
echo '  5) Fix the names of the passport SAML encryption certs'
