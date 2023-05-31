
# Installs and updates Gluu + Sign In Canada on a new VM

package_url=${1}
package=$(basename ${package_url})

echo "Installing Gluu Server"
rpm --import https://repo.gluu.org/rhel/RPM-GPG-KEY-GLUU
if grep Red /etc/redhat-release ; then
   wget -nv https://repo.gluu.org/rhel/7/gluu-server-4.4.0-rhel7.x86_64.rpm -O gluu-server-4.4.0-rhel7.x86_64.rpm
else
   wget -nv https://repo.gluu.org/centos/7/gluu-server-4.4.0-centos7.x86_64.rpm -O gluu-server-4.4.0-centos7.x86_64.rpm 
fi
echo "Checking integrity of the Gluu RPM..."
rpm -K ./gluu-server-4.4.0-*.x86_64.rpm
if [ $? -eq 0 ] ; then
   echo "Passed."
else
   echo "Failed. Aborting!"
   exit 1
fi
yum install -y gluu-server-4.4.0-*.x86_64.rpm

while [ ! -f /opt/gluu-server/install/community-edition-setup/setup.py ] ; do
   echo "Gluu Setup was not extracted. Trying again..."
   # RPM is supposed to do this but sometimes doesn't. I think becasue the containter is not ready yet.
   sleep 5
   ssh -t -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                  -o PubkeyAuthentication=yes root@localhost '/opt/gluu/bin/install.py'
done

# Download the product tarball
echo Downloading ${package}...
wget -nv ${package_url} -O ${package}
if [ $? -ne 0 ] ; then
   echo "package download failed. Aborting!"
   exit 1
fi

wget -nv ${package_url}.sha -O ${package}.sha
if [ $? -ne 0 ] ; then
   echo "package hash download failed. Aborting!"
   exit 1
fi

echo -n "Checking download integrity..."
if [ "$(cut -d ' ' -f 2 ${package}.sha)" = "$(openssl sha256 ${package} | cut -d ' ' -f 2)" ] ; then
   echo "Passed."
else
   echo "Failed!. Aborting installation."
   exit 1
fi

echo "Installing Sign In Canada customizations..."
tar xvzf ${package} -C /opt/gluu-server/

echo "Installing & Updating Container packages..."
ssh  -T -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PubkeyAuthentication=yes root@localhost <<-EOF
   yum clean all
   echo "Installing logstash"
   rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
   yum install -y jq https://artifacts.elastic.co/downloads/logstash/logstash-8.7.0-x86_64.rpm
   /usr/share/logstash/bin/logstash-plugin install logstash-filter-json_encode microsoft-logstash-output-azure-loganalytics
   sed -i "s/^# api\.enabled: true/api\.enabled: false/" /etc/logstash/logstash.yml
   echo "Updating Corretto"
   rm -f /opt/dist/app/amazon-corretto-*.tar.gz
   wget -q https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz -P /opt/dist/app
   wget -q https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz.sig -P /tmp
   gpg2 --fetch-keys https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz.pub
   echo "Checking Corretto file integritiy..."
   gpg2 --verify /tmp/amazon-corretto-11-x64-linux-jdk.tar.gz.sig /opt/dist/app/amazon-corretto-11-x64-linux-jdk.tar.gz
   if [ $? -eq 0 ] ; then
      echo "Passed."
   else
      echo "Failed. Aborting!"
      exit 1
   fi
   echo "Installing AWS CLI"
   curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
   unzip -q /tmp/awscliv2.zip -d /tmp
   /tmp/aws/install
   yum update -y
EOF
