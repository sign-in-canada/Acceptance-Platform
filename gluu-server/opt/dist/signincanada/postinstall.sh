#!/bin/sh

echo 'Stopping services...'
systemctl stop httpd oxauth identity idp passport

echo 'Enabling the keyvault service...'
systemctl enable keyvault

if [ -d /opt/shibboleth-idp ] ; then
echo 'Installing custom libs into Shibboleth...'
    install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
    install -m 644 -o jetty -g jetty /opt/dist/signincanada/shib-oxauth-authn3-4.1.0.sic1.jar /opt/gluu/jetty/idp/custom/libs
    install -m 644 -o jetty -g jetty  /opt/dist/signincanada/applicationinsights-web-auto-2.6.1.jar /opt/gluu/jetty/idp/custom/libs
fi

echo 'Installing custom libs into oxAuth...'
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-web-auto-2.6.1.jar /opt/gluu/jetty/oxauth/custom/libs

echo 'Installing audit logging patch...'
pushd /opt/dist/gluu/patch > /dev/null 2>&1
zip -u /opt/gluu/jetty/oxauth/webapps/oxauth.war WEB-INF/classes/org/gluu/oxauth/audit/ApplicationAuditLogger.class
popd > /dev/null 2>&1

echo 'Updating Corretto...'
rm -f /opt/jre
rm -rf /opt/amazon-corretto-*
tar xf /opt/dist/corretto/amazon-corretto-8-x64-linux-jdk.tar.gz -C /opt
ln -s /opt/amazon-corretto-* /opt/jre

echo 'Installing the UI...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo 'Removing unused Gluu authentication pages...'
zip -d -q /opt/gluu/jetty/oxauth/webapps/oxauth.war "/auth/*"

echo 'Removing oxTrust log settings page...'
zip -d -q /opt/gluu/jetty/identity/webapps/identity.war "/logviewer/configureLogViewer.xhtml"

if [ -d /opt/shibboleth-idp ] ; then
    echo 'Configuring Shibboleth...'
    install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
    install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
    install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn
fi

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo 'Done.'
