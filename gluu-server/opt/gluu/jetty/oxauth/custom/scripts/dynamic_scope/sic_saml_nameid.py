# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Pawel Pietrzynski
#

from org.gluu.model.custom.script.type.scope import DynamicScopeType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import ClientService
from org.gluu.util import StringHelper
from java.util import Arrays
from org.json import JSONObject

import sys, json

class DynamicScope(DynamicScopeType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print ("Dynamic scope [saml_nameid]. Initialization")
        # Keep an in-memory cache of RP Configs
        self.rpConfigCache = {}

        return True   

    def destroy(self, configurationAttributes):
        print ("Dynamic scope [saml_nameid]. Destroy")
        return True   

    # Update Json Web token before signing/encrypring it
    #   dynamicScopeContext is org.gluu.oxauth.service.external.context.DynamicScopeExternalContext
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def update(self, dynamicScopeContext, configurationAttributes):
        # Get the client and SAML affilitation value
        authorizationGrant = dynamicScopeContext.getAuthorizationGrant()
        rpConfig = self.getRPConfig(authorizationGrant.getClient())
        collectSpNameQualifier = rpConfig.get("collect")
        
        # if collectSpNameQualifier is not empty, we pass the affiliated SAML nameid
        if collectSpNameQualifier is not None:
            # then we look for the SAML persistentId value in user profile
            user = dynamicScopeContext.getUser()
            userPersistentIds = user.getAttributeValues("persistentId")
            if userPersistentIds is not None and userPersistentIds.size > 0:
                # go through existing user persistentIds
                for userPersistentId in userPersistentIds:
                    # Format is : persistentIdSamlSpNQ|persistentIdIdp|persistentIdUid
                    samlSpNameQualifier, samlIDPNameQualifier, samlSpNameIDSubject = tuple(userPersistentId.split("|"))
                    # if the current RP already has a mapping then skip the second phase
                    if samlSpNameQualifier == collectSpNameQualifier:
                        # create a JSON object with the full NameID object
                        samlNameIdJson = '{"SPNameQualifier":"%s","NameQualifier":"%s","value":"%s"}' % (samlSpNameQualifier, samlIDPNameQualifier, samlSpNameIDSubject )
                        samlNameId = JSONObject(samlNameIdJson)
                        # Add the saml_nameid value to the result if present
                        jsonWebResponse = dynamicScopeContext.getJsonWebResponse()
                        claims = jsonWebResponse.getClaims()
                        claims.setClaim("saml_nameid", samlNameId)

        return True

    def getSupportedClaims(self, configurationAttributes):
        return Arrays.asList("saml_nameid")

    def getApiVersion(self):
        return 11

    def getRPConfig(self, client):
        clientService = CdiUtil.bean(ClientService)

        # check the cache
        clientKey = "oidc:%s" % client.getClientId()
        if clientKey in self.rpConfigCache:
            return self.rpConfigCache[clientKey]

        descriptionAttr = clientService.getCustomAttribute(client, "description")

        rpConfig = None
        if descriptionAttr is not None:
            description = descriptionAttr.getValue()
            start = description.find("{")
            if (start > -1):
                decoder = json.JSONDecoder()
                try:
                    rpConfig, _ = decoder.raw_decode(description[start:])
                except ValueError:
                    print ("%s. getRPConfig: Failed to parse JSON config for client %s" % (self.name, client.getClientName()))
                    print ("Exception: ", sys.exc_info()[1])

        if rpConfig is None:
            rpConfig = {}

        # Add it to the cache
        self.rpConfigCache[clientKey] = rpConfig
        return rpConfig
