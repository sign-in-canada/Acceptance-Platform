#!/bin/bash

/opt/couchbase/bin/cbq -u $1 -p $2 -s "SELECT gluu.* FROM gluu WHERE objectClass='oxAuthClient' AND oxdId = ''" > $3
echo "Don't forget to save the client secret salt"
