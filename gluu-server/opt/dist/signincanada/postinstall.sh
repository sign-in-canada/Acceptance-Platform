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
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.3.jar /opt/gluu/jetty/oxauth/custom/libs
if [ -d /opt/gluu/jetty/idp ] ; then
   echo 'Installing custom libs into Shibboleth...'
   install -m 755 -o jetty -g jetty -d /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/dist/signincanada/shib-oxauth-authn3-4.2.3.sic1.jar /opt/gluu/jetty/idp/custom/libs
   install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-core-2.6.3.jar /opt/gluu/jetty/idp/custom/libs
fi

echo 'Preparing to patch Gluu web archives'
mkdir -p /tmp/patch/oxauth
unzip -q /opt/dist/gluu/oxauth.war -d /tmp/patch/oxauth
mkdir -p /tmp/patch/identity
unzip -q /opt/dist/gluu/identity.war -d /tmp/patch/identity
if [ -d /opt/gluu/jetty/idp ] ; then
   mkdir -p /tmp/patch/idp
   unzip -q /opt/dist/gluu/idp.war -d /tmp/patch/idp
fi

echo 'Updating the Couchbase client...'
rm -v /tmp/patch/oxauth/WEB-INF/lib/java-client-*.jar
rm -v /tmp/patch/oxauth/WEB-INF/lib/core-io-*.jar
cp -v /opt/dist/app/java-client-2.7.22.jar /tmp/patch/oxauth/WEB-INF/lib
cp -v /opt/dist/app/core-io-1.7.22.jar /tmp/patch/oxauth/WEB-INF/lib
rm -v /tmp/patch/identity/WEB-INF/lib/java-client-*.jar
rm -v /tmp/patch/identity/WEB-INF/lib/core-io-*.jar
cp -v /opt/dist/app/java-client-2.7.22.jar /tmp/patch/identity/WEB-INF/lib
cp -v /opt/dist/app/core-io-1.7.22.jar /tmp/patch/identity/WEB-INF/lib
if [ -d /opt/gluu/jetty/idp ] ; then
   rm -v /tmp/patch/idp/WEB-INF/lib/java-client-*.jar
   rm -v /tmp/patch/idp/WEB-INF/lib/core-io-*.jar
   cp -v /opt/dist/app/java-client-2.7.22.jar /tmp/patch/idp/WEB-INF/lib
   cp -v /opt/dist/app/core-io-1.7.22.jar /tmp/patch/idp/WEB-INF/lib
fi

echo 'Updating log4j'
rm -v /tmp/patch/oxauth/WEB-INF/lib/log4j-api-*.jar
rm -v /tmp/patch/oxauth/WEB-INF/lib/log4j-1.2-api-*.jar
rm -v /tmp/patch/oxauth/WEB-INF/lib/log4j-core-*.jar
rm -v /tmp/patch/oxauth/WEB-INF/lib/log4j-slf4j-impl-*.jar
rm -v /tmp/patch/oxauth/WEB-INF/lib/log4j-jul-*.jar
cp -v /opt/dist/app/log4j-api-2.17.1.jar /tmp/patch/oxauth/WEB-INF/lib
cp -v /opt/dist/app/log4j-1.2-api-2.17.1.jar /tmp/patch/oxauth/WEB-INF/lib
cp -v /opt/dist/app/log4j-core-2.17.1.jar /tmp/patch/oxauth/WEB-INF/lib
cp -v /opt/dist/app/log4j-slf4j-impl-2.17.1.jar /tmp/patch/oxauth/WEB-INF/lib
cp -v /opt/dist/app/log4j-jul-2.17.1.jar /tmp/patch/oxauth/WEB-INF/lib

rm -v /tmp/patch/identity/WEB-INF/lib/log4j-api-*.jar
rm -v /tmp/patch/identity/WEB-INF/lib/log4j-1.2-api-*.jar
rm -v /tmp/patch/identity/WEB-INF/lib/log4j-core-*.jar
rm -v /tmp/patch/identity/WEB-INF/lib/log4j-slf4j-impl-*.jar
cp -v /opt/dist/app/log4j-api-2.17.1.jar /tmp/patch/identity/WEB-INF/lib
cp -v /opt/dist/app/log4j-1.2-api-2.17.1.jar /tmp/patch/identity/WEB-INF/lib
cp -v /opt/dist/app/log4j-core-2.17.1.jar /tmp/patch/identity/WEB-INF/lib
cp -v /opt/dist/app/log4j-slf4j-impl-2.17.1.jar /tmp/patch/identity/WEB-INF/lib

if [ -d /opt/gluu/jetty/idp ] ; then
   rm -v /tmp/patch/idp/WEB-INF/lib/log4j-api-*.jar
   rm -v /tmp/patch/idp/WEB-INF/lib/log4j-1.2-api-*.jar
   rm -v /tmp/patch/idp/WEB-INF/lib/log4j-core-*.jar
   rm -v /tmp/patch/idp/WEB-INF/lib/log4j-over-slf4j-*.jar
   cp -v /opt/dist/app/log4j-api-2.17.1.jar /tmp/patch/idp/WEB-INF/lib
   cp -v /opt/dist/app/log4j-1.2-api-2.17.1.jar /tmp/patch/idp/WEB-INF/lib
   cp -v /opt/dist/app/log4j-core-2.17.1.jar /tmp/patch/idp/WEB-INF/lib
   cp -v /opt/dist/app/log4j-over-slf4j-1.7.32.jar /tmp/patch/idp/WEB-INF/lib
fi

echo 'Rebuilding Gluu web archives'
rm -rf /opt/jetty-9.4/temp/*
pushd /tmp/patch/oxauth
rm -v /opt/gluu/jetty/oxauth/webapps/oxauth.war
/opt/jre/bin/jar -cvf /opt/gluu/jetty/oxauth/webapps/oxauth.war * > /dev/null
popd 2>&1

pushd /tmp/patch/identity
rm -v /opt/gluu/jetty/identity/webapps/identity.war
/opt/jre/bin/jar -cvf /opt/gluu/jetty/identity/webapps/identity.war * > /dev/null
popd 2>&1

if [ -d /opt/gluu/jetty/idp ] ; then
   pushd /tmp/patch/idp
   rm -v /opt/gluu/jetty/idp/webapps/idp.war
   /opt/jre/bin/jar -cvf /opt/gluu/jetty/idp/webapps/idp.war * > /dev/null
   popd 2>&1
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
yum update -y
echo 'Done.'
