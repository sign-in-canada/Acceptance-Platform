#!/bin/sh

umask 22
echo 'Stopping services...'
systemctl stop httpd oxauth identity fido2 idp passport

echo 'Clearing jetty temp files'
rm -rf /opt/jetty-9.4/temp/*

echo 'Enabling the keyvault service...'
if grep Red /etc/redhat-release ; then
   yum remove -y epel-release
fi
yum clean all
yum install -y /opt/dist/app/oniguruma-6.8.2-1.el7.x86_64.rpm /opt/dist/app/jq-1.6-2.el7.x86_64.rpm
systemctl enable keyvault

echo 'Installing logstash...'
rpm --import /etc/pki/rpm-gpg/GPG-KEY-elasticsearch
yum install -y /opt/dist/app/logstash-*-x86_64.rpm
/usr/share/logstash/bin/logstash-plugin install file:///opt/dist/app/logstash-offline-plugins-8.2.2.zip
sed -i "s/^# api\.enabled: true/api\.enabled: false/" /etc/logstash/logstash.yml
systemctl enable logstash

echo 'Enabling the couchbase health check service...'
systemctl enable cbcheck

echo "Enabling the passport key extraction service"
systemctl enable passportkeys

echo 'Installing the Application Insights SDK to oxAuth...'
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.4.jar /opt/gluu/jetty/oxauth/custom/libs
sed -i "10i\        <Set name=\"extraClasspath\">custom/libs/applicationinsights-core-2.6.4.jar</Set>" /opt/gluu/jetty/oxauth/webapps/oxauth.xml
if [ -d /opt/gluu/jetty/idp ] ; then
   echo 'Installing the Application Insights SDK into Shibboleth...'
   install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.4.jar /opt/gluu/jetty/idp/custom/libs
   sed -i "10i\        <Set name=\"extraClasspath\">custom/libs/applicationinsights-core-2.6.4.jar</Set>" /opt/gluu/jetty/idp/webapps/idp.xml
fi

echo "Patching fido2 log4j configuration"
rm -rf /opt/jetty-9.4/temp/*
if [ -d /opt/gluu/jetty/fido2 ] ; then
   mkdir -p /tmp/patch/fido2
   pushd /tmp/patch/fido2
   /opt/jre/bin/jar -xf /opt/dist/gluu/fido2.war
   sed -i 's/\${log4j\.default\.log\.level}/INFO/g' ./WEB-INF/classes/log4j2.xml
   rm -v /opt/gluu/jetty/fido2/webapps/fido2.war
   /opt/jre/bin/jar -cf /opt/gluu/jetty/fido2/webapps/fido2.war *
   popd 2>&1
   rm -rf /tmp/patch/fido2
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

echo "Configuring Couchbase scan consistency"
sed -i 's/not_bounded/request_plus/g' /etc/gluu/conf/gluu-couchbase.properties

echo "Updating packages..."
if grep Red /etc/redhat-release ; then
   yum remove -y epel-release
fi
yum clean all
yum install -y jq
yum update -y
echo 'Done.'
