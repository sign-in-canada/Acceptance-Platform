#!/bin/bash

/opt/couchbase/bin/cbimport json -c couchbase://localhost -u $1 -p $2 -b gluu -f list -g "clients_%inum%" -d file://$3

