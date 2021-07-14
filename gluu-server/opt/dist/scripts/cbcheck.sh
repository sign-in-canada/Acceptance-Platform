#!/bin/bash
#
# Perform a Couchbase health check before starting Gluu
#

GCB="/etc/gluu/conf/gluu-couchbase.properties"
ENCODE_PY="/opt/gluu/bin/encode.py"
export CB_REST_USERNAME=Administrator

testConnection () {
   for retries in {1..60} ; do
      http_code=$(curl -s -k -o /dev/null -w "%{http_code}\n" -u ${CB_REST_USERNAME}:${CB_REST_PASSWORD} https://${1}:18091/pools)
      if [ ${http_code} -eq 200 ]; then
         echo "Connected successfully to $1!"
         return 0
      fi
      sleep 60
   done
   return 1
}

test_cb_servers () {
   for cb_host in $(echo $1 | sed "s/,/ /g") ; do
      echo "Checking Couchbase connection for $cb_host server"
      # Test server connection
      testConnection "$cb_host"
      if [ $? -eq 1 ]; then
         echo "Couchbase health check failed: could not connect to $cb_host."
         exit 1
      fi
   done
   echo "Couchbase health check is successful"
}

if [ ! -f $GCB -o ! -f $ENCODE_PY ]; then
   echo "Couchbase health check failed due a missing file. Aborting."
   exit 1
fi

# Get the Couchbase admin password
encoded_pwd=$(grep auth.userPassword $GCB | awk '{print $2}')
export CB_REST_PASSWORD=$($ENCODE_PY -D $encoded_pwd)

# Get the Couchbase servers list
cb_servers=$(grep servers $GCB | cut -d ':' -f 2)

# Perform a Couchbase health check
test_cb_servers "$cb_servers"

exit 0