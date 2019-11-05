# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Pawel Pietrzynski
#

from org.gluu.model.custom.script.type.scope import DynamicScopeType
from org.gluu.oxauth.service import UserService
from org.gluu.util import StringHelper, ArrayHelper
from java.util import Arrays, ArrayList
from org.json import JSONObject

import java
import time

class DynamicScope(DynamicScopeType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Dynamic scope [claims_scope]. Initialization"

        return True   

    def destroy(self, configurationAttributes):
        print "Dynamic scope [claims_scope]. Destroy"
        return True   

    # Update Json Web token before signing/encrypring it
    #   dynamicScopeContext is org.gluu.oxauth.service.external.context.DynamicScopeExternalContext
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def update(self, dynamicScopeContext, configurationAttributes):
        print "Dynamic scope [claims_scope]. Update method"

        # Get the client and session and dynamic claims
        authorizationGrant = dynamicScopeContext.getAuthorizationGrant()
        oidcClient = authorizationGrant.getClient()
        currentEntityId = "oidc:%s" % oidcClient.getClientName()
        
        # sessionDn = authorizationGrant.getSessionDn()
        # print "Dynamic scope [claims_scope]. Got session DN = '%s'" % sessionDn
        # sessionId = dynamicScopeContext.getEntryAttributeValue(sessionDn, "sessionId")
        # if ( sessionDn != None ):

        # prepare the search results attributes
        claimNamesJsonString = None
        claimsSrcJsonString = None
        
        # then we look for the SAML persistentId value in user profile
        user = dynamicScopeContext.getUser()
        userTransientIds = user.getAttributeValues("transientId")
        if ( userTransientIds != None ):
            if ( userTransientIds.size > 0 ):
                # save latest time (set to 0 initially)
                latestExpiryTimeSec = 0
                # go through existing user persistentIds
                for userTransientId in userTransientIds:
                    # if the current RP already has a mapping then skip the second phase
                    transientIdRp = StringHelper.split(userTransientId,'|')[0]
                    if ( transientIdRp == currentEntityId ):
                        print "Dynamic scope [claims_scope]. Found matching transientId '%s'" % userTransientId
                        # Format is : currentOidcRp, expiryTimeSec, userInfoUrl, accessToken
                        expiryTimeSec = StringHelper.split(userTransientId,'|')[1]
                        userInfoUrl   = StringHelper.split(userTransientId,'|')[2]
                        accessToken   = StringHelper.split(userTransientId,'|')[3]
                        # Check the last timestamp is newer than the current one and not older than 15 minutes (900 second)
                        expiryTimeSec = StringHelper.toInteger(expiryTimeSec)
                        currenttimeSec = int(round(time.time()))
                        if ( expiryTimeSec > latestExpiryTimeSec and expiryTimeSec > (currenttimeSec - 900) ):
                            # Save expiry and update/set the _claim_sources parameters
                            latestExpiryTimeSec = expiryTimeSec
                            # create a JSON object with _claim_sources for distributed claims
                            claimsSrcJsonString = '{"src1":{"endpoint":"%s","access_token":"%s"}}' % ( userInfoUrl, accessToken )
                            
                            # Set the _claim_names value to the result - static as per PCTF
                            #######################################################
                            #   "_claim_names": {
                            #     "given_name": "src1",
                            #     "family_name": "src1",
                            #     "birthdate": "src1",
                            #     "address": "src1"
                            #   },
                            # create a JSON object with _claim_sources for distributed claims
                            claimNamesJsonString = '{"given_name":"src1","family_name":"src1","birthdate":"src1","address":"src1"}'

        # set the claims if they have been found
        if ( claimNamesJsonString != None and claimsSrcJsonString != None ):
            # Get the claims object
            jsonWebResponse = dynamicScopeContext.getJsonWebResponse()
            claims = jsonWebResponse.getClaims()
            # create JSON objects
            claimNamesJson = JSONObject(claimNamesJsonString)
            claimsSrcJson = JSONObject(claimsSrcJsonString)
            # set the claims
            claims.setClaim("_claim_names", claimNamesJson)
            claims.setClaim("_claim_sources", claimsSrcJson)

        return True

    def getSupportedClaims(self, configurationAttributes):
        print "Dynamic scope [claims_scope]. Get supported claims = '_claim_names,_claim_sources'"
        return Arrays.asList("_claim_names","_claim_sources")

    def getApiVersion(self):
        return 2