#!/bin/sh

echo 'Stopping services...'
systemctl stop httpd oxauth identity idp passport

echo 'Enabling the keyvault service...'
systemctl enable keyvault

echo 'Installing custom libs into Shibboleth and oxAuth...'
install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty /opt/dist/signincanada/shib-oxauth-authn3-4.1.0.sic1.jar /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty  /opt/dist/signincanada/applicationinsights-web-auto-2.5.1.jar /opt/gluu/jetty/idp/custom/libs
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-web-auto-2.5.1.jar /opt/gluu/jetty/oxauth/custom/libs

echo 'Updating Corretto...'
rm -f /opt/jre
rm -rf /opt/amazon-corretto-*
tar xf /opt/dist/corretto/amazon-corretto-8-x64-linux-jdk.tar.gz -C /opt
ln -s /opt/amazon-corretto-* /opt/jre

echo 'Installing the UI...'
chgrp gluu /etc/gluu/select_page_content.json
chmod 644 /etc/gluu/select_page_content.json
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo 'Configuring Shibboleth...'
install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo 'Done.'
