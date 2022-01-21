#!/bin/sh

umask 22
echo 'Stopping services...'
systemctl stop httpd oxauth identity idp passport

echo 'Enabling the keyvault service...'
if grep Red /etc/redhat-release ; then
   yum remove -y epel-release
fi
yum clean all
yum install -y /opt/dist/app/oniguruma-6.8.2-1.el7.x86_64.rpm /opt/dist/app/jq-1.6-2.el7.x86_64.rpm
systemctl enable keyvault

echo 'Enabling the couchbase health check service...'
systemctl enable cbcheck

echo "Enabling the passport key extraction service"
systemctl enable passportkeys

echo 'Installing the Application Insights SDK to oxAuth...'
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.4.jar /opt/gluu/jetty/oxauth/custom/libs
if [ -d /opt/gluu/jetty/idp ] ; then
   echo 'Installing custom libs into Shibboleth...'
   install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/dist/signincanada/shib-oxauth-authn3-4.2.3.sic1.jar /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.4.jar /opt/gluu/jetty/idp/custom/libs
fi

echo 'Preparing to patch Gluu web archives'
mkdir -p /tmp/patch/oxauth
unzip -q /opt/dist/gluu/oxauth.war -d /tmp/patch/oxauth
mkdir -p /tmp/patch/identity
unzip -q /opt/dist/gluu/identity.war -d /tmp/patch/identity
if [ -d /opt/gluu/jetty/fido2 ] ; then
   mkdir -p /tmp/patch/fido2
   unzip -q /opt/dist/gluu/fido2.war -d /tmp/patch/fido2
fi
if [ -d /opt/gluu/jetty/idp ] ; then
   mkdir -p /tmp/patch/idp
   unzip -q /opt/dist/gluu/idp.war -d /tmp/patch/idp
fi

echo 'Installing the UI...'
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

if [ -d /opt/shibboleth-idp/conf ] ; then
   echo 'Configuring Shibboleth...'
   install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn
fi

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo "Updating packages..."
if grep Red /etc/redhat-release ; then
   yum remove -y epel-release
fi
yum clean all
yum install -y jq
yum update -y
echo 'Done.'
