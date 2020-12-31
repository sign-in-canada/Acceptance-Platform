#!/bin/sh

echo 'Stopping services...'
systemctl stop httpd oxauth identity idp passport

echo 'Enabling the keyvault service...'
systemctl enable keyvault

echo 'Installing custom libs into Shibboleth and oxAuth...'
install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty /opt/dist/signincanada/shib-oxauth-authn3-4.2.2.sic1.jar /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty  /opt/dist/signincanada/applicationinsights-web-auto-2.6.1.jar /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-web-auto-2.6.1.jar /opt/gluu/jetty/oxauth/custom/libs

echo 'Installing the UI...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo 'Removing unused Gluu authentication pages...'
zip -d -q /opt/gluu/jetty/oxauth/webapps/oxauth.war "/auth/*"

echo 'Configuring Shibboleth...'
install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo "Updating packages..."
yum clean all
yum update -y
echo 'Done.'
