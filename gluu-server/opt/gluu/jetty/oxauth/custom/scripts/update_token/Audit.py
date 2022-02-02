# Author: Doug Harris
#
#

from org.gluu.model.custom.script.type.token import UpdateTokenType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.model.token import JwrService

from com.microsoft.applicationinsights import TelemetryClient

class UpdateToken(UpdateTokenType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        

    def init(self, customScript, configurationAttributes):
        self.name = customScript.getName()

        print ("%s: Initializing" % self.name)
        self.telemetryClient = TelemetryClient()
        return True

    def destroy(self, configurationAttributes):
        print ("%s: Destroyed" % self.name)
        return True

    def getApiVersion(self):
        return 11

    # Logs a custom event containing the JWT header and payload
    def modifyIdToken(self, jsonWebResponse, context):
        jwrService = CdiUtil.bean(JwrService)

        client = context.getClient()
        signedJWT = jwrService.encode(jsonWebResponse, client)
        eventProperties = {"client": client.getClientName(),
                           "header": signedJWT.getHeader().toJsonString(),
                           "payload": signedJWT.getClaims().toJsonString(),
                           "signature": signedJWT.getEncodedSignature()}

        print(eventProperties)
        self.telemetryClient.trackEvent("ID Token", eventProperties, None)
        
        return False
