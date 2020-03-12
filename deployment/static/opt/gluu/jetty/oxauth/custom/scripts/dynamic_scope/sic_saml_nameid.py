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

class DynamicScope(DynamicScopeType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Dynamic scope [saml_nameid_scope]. Initialization"

        return True   

    def destroy(self, configurationAttributes):
        print "Dynamic scope [saml_nameid_scope]. Destroy"
        return True   

    # Update Json Web token before signing/encrypring it
    #   dynamicScopeContext is org.gluu.oxauth.service.external.context.DynamicScopeExternalContext
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def update(self, dynamicScopeContext, configurationAttributes):
        print "Dynamic scope [saml_nameid_scope]. Update method"

        # Get the client and SAML affilitation value
        authorizationGrant = dynamicScopeContext.getAuthorizationGrant()
        oidcClient = authorizationGrant.getClient()
        samlSpNameQualifier = oidcClient.getPolicyUri()
        
        # if samlSpNameQualifier is not empty, we pass the affiliated SAML nameid
        if ( samlSpNameQualifier != None ):
            # then we look for the SAML persistentId value in user profile
            print "Dynamic scope [saml_nameid_scope]. Found SPNameQualifier parameter '%s'" % samlSpNameQualifier
            user = dynamicScopeContext.getUser()
            userPersistentIds = user.getAttributeValues("persistentId")
            print "Dynamic scope [saml_nameid_scope]. Found SPNameQualifier parameter"
            if ( userPersistentIds != None ):
                if ( userPersistentIds.size > 0 ):
                    # go through existing user persistentIds
                    for userPersistentId in userPersistentIds:
                        # if the current RP already has a mapping then skip the second phase
                        if ( userPersistentId.find(samlSpNameQualifier) > -1 ):
                            print "Dynamic scope [saml_nameid_scope]. Found matching persistentId '%s'" % userPersistentId
                            # Format is : persistentIdSamlSpNQ|persistentIdIdp|persistentIdUid
                            samlSpNameQualifier  = StringHelper.split(userPersistentId,'|')[0]
                            samlIDPNameQualifier = StringHelper.split(userPersistentId,'|')[1]
                            samlSpNameIDSubject  = StringHelper.split(userPersistentId,'|')[2]
                            # create a JSON object with the full NameID object
                            samlNameIdJson = '{"SPNameQualifier":"%s","NameQualifier":"%s","value":"%s"}' % (samlSpNameQualifier, samlIDPNameQualifier, samlSpNameIDSubject )
                            samlNameId = JSONObject(samlNameIdJson)
                            # Add the saml_nameid value to the result if present
                            jsonWebResponse = dynamicScopeContext.getJsonWebResponse()
                            claims = jsonWebResponse.getClaims()
                            claims.setClaim("saml_nameid", samlNameId)

        return True

    def getSupportedClaims(self, configurationAttributes):
        print "Dynamic scope [saml_nameid_scope]. Get supported claims = 'saml_nameid'"
        return Arrays.asList("saml_nameid")

    def getApiVersion(self):
        return 2