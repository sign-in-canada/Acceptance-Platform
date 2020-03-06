#!/bin/bash

/opt/couchbase/bin/cbexport json -c couchbase://localhost -u $1 -p $2 -b gluu_user -f lines --include-key cbkey -o $3
sed -i -e '/Gluu Manager Group/d' -e '/Default Admin User/d' $3

