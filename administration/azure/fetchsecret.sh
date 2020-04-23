#!/bin/bash
#
# Fetch a secret from Azure KeyVault
#
# Arguments:
#
# fetchSecret [secret name]

source /etc/default/azure

API_VER='7.0'

# Obtain an access token
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true | jq -r '.access_token')

curl -s -H "Authorization: Bearer ${TOKEN}" ${KEYVAULT}/secrets/${1}?api-version=${API_VER} \
   | jq -r '.value'
