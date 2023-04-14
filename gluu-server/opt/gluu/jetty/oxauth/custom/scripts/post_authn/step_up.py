# Author: Doug Harris
#

from org.gluu.model.custom.script.type.postauthn import PostAuthnType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service.external import ExternalAuthenticationService

import sys

class PostAuthn(PostAuthnType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        self.name = customScript.getName()
        print ("%s: Initializing" % self.name)
        externalAuthenticationService = CdiUtil.bean(ExternalAuthenticationService)
        self.acrLevels = externalAuthenticationService.acrToLevelMapping()
        return True

    def destroy(self, configurationAttributes):
        print ("%s: Destroyed" % self.name)
        return True

    def getApiVersion(self):
        return 11

    # Check client's default ACR values and force authn if needed
    def forceReAuthentication(self, context):
        client = context.getClient()
        sessionAttributes = context.getSession().getSessionAttributes()
        defaultAcrValues = client.getDefaultAcrValues()
        sessionAcr = sessionAttributes.get("acr")

        if defaultAcrValues and sessionAcr not in defaultAcrValues:
            for allowedAcr in defaultAcrValues:
                if self.acrLevels[sessionAcr] >= self.acrLevels[allowedAcr]:
                    return False

            return True

        return False

    def forceAuthorization(self, context):
        return False
