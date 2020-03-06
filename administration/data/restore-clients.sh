#!/bin/bash

/opt/couchbase/bin/cbimport json -c couchbase://localhost -u $1 -p $2 -b gluu_user -f list -g "%clients_%inum%" -d file://$3

