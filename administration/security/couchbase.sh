#!/bin/bash
export CB_REST_USERNAME=$1
export CB_REST_PASSWORD=$2

/opt/couchbase/bin/couchbase-cli  setting-autofailover -c localhost:8091 --enable-auto-failover 0

/opt/couchbase/bin/couchbase-cli  node-to-node-encryption -c localhost:8091 --enable

/opt/couchbase/bin/couchbase-cli setting-security -c localhost:8091 --set \
  --disable-http-ui 1 \
  --tls-min-version tlsv1.2 \
  --set --tls-honor-cipher-order 1 \
  --cipher-suites TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 \
  --cluster-encryption-level all

/opt/couchbase/bin/couchbase-cli  setting-autofailover -c localhost:8091 \
  --enable-auto-failover 1 \
  --auto-failover-timeout 120 \
  --enable-failover-of-server-groups 1 \
  --max-failovers 2 \
  --can-abort-rebalance 1
  