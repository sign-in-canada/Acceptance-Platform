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

echo 'Installing and configuring logstash...'
rpm --import /etc/pki/rpm-gpg/GPG-KEY-elasticsearch
yum install -y /opt/dist/app/logstash-*-x86_64.rpm
/usr/share/logstash/bin/logstash-plugin install file:///opt/dist/app/logstash-offline-plugins-8.3.2.zip
sed -i "s/^# api\.enabled: true/api\.enabled: false/" /etc/logstash/logstash.yml
mkdir /etc/systemd/system/logstash.service.d
echo "[Unit]" > /etc/systemd/system/logstash.service.d/override.conf
echo "After=keyvault.service" >> /etc/systemd/system/logstash.service.d/override.conf
echo >> /etc/systemd/system/logstash.service.d/override.conf
echo "[Service]" >> /etc/systemd/system/logstash.service.d/override.conf
echo "EnvironmentFile=/run/keyvault/secrets/LogWorkspaceKey" >> /etc/systemd/system/logstash.service.d/override.conf
install -m 644 /opt/dist/signincanada/logstash/* /etc/logstash/conf.d
echo '*.*          @127.0.0.1:1514' > /etc/rsyslog.d/logstash.conf
systemctl enable logstash

echo 'Enabling the couchbase health check service...'
systemctl enable cbcheck

echo "Enabling the passport key extraction service"
systemctl enable passportkeys

echo 'Installing the Custom UI and dependencies...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

if [ -d /opt/gluu/jetty/idp ] ; then
   echo 'Installing the Application Insights SDK into Shibboleth...'
   install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/gluu/jetty/oxauth/custom/libs/applicationinsights-core-*.jar /opt/gluu/jetty/idp/custom/libs
fi

echo 'Installing the Notify service...'
mkdir -p /opt/gluu/node/gc/notify/logs
tar xzf /opt/dist/signincanada/node-services.tgz -C /opt/gluu/node/gc/notify
chown -R node:node /opt/gluu/node/gc
cp /opt/dist/signincanada/notify-config.json /etc/gluu/conf
systemctl enable notify

echo 'Removing unused Gluu authentication pages...'
zip -d -q /opt/gluu/jetty/oxauth/webapps/oxauth.war "/auth/*"
chown jetty:gluu /opt/gluu/jetty/oxauth/webapps/oxauth.war

if [ -d /opt/shibboleth-idp/conf ] ; then
   echo 'Configuring Shibboleth...'
   install  -m 444 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.xml /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/*.js /opt/shibboleth-idp/conf
   install  -m 644 -o jetty -g jetty /opt/dist/signincanada/shibboleth-idp/conf/authn/*.xml /opt/shibboleth-idp/conf/authn
fi

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo "Configuring and trusting TBS CA certificate"
install -m 640 -o root -g gluu /opt/dist/certs/tbs-ca.pem /etc/certs/tbs-ca.crt
cat /opt/dist/certs/tbs-chain.pem >> /etc/certs/tbs-ca.crt
/opt/jre/bin/keytool -import -trustcacerts -alias tbsrootca -file /opt/dist/certs/tbs-ca.pem -cacerts -noprompt -storepass changeit
/opt/jre/bin/keytool -import -trustcacerts -alias tbschain -file /opt/dist/certs/tbs-chain.pem -cacerts -noprompt -storepass changeit

echo "Configuring Couchbase scan consistency"
sed -i 's/not_bounded/request_plus/g' /etc/gluu/conf/gluu-couchbase.properties

echo "Updating packages..."
yum update -y
echo 'Done.'
