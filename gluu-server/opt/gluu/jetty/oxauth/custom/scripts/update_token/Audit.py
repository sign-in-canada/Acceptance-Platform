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

        if jsonWebResponse.getClaims().hasClaim("sid"):
            eventProperties["sid"] = jsonWebResponse.getClaims().getClaimAsString("sid")

        self.telemetryClient.trackEvent("ID Token", eventProperties, None)

        return False

    # Returns boolean, true - indicates that script applied changes. If false is returned token will not be created.
    # refreshToken is reference of io.jans.as.server.model.common.RefreshToken (note authorization grant can be taken as context.getGrant())
    # context is reference of io.jans.as.server.service.external.context.ExternalUpdateTokenContext (in https://github.com/JanssenProject/jans-auth-server project, )
    def modifyRefreshToken(self, refreshToken, context):
        return True

    # Returns boolean, true - indicates that script applied changes. If false is returned token will not be created.
    # accessToken is reference of io.jans.as.server.model.common.AccessToken (note authorization grant can be taken as context.getGrant())
    # context is reference of io.jans.as.server.service.external.context.ExternalUpdateTokenContext (in https://github.com/JanssenProject/jans-auth-server project, )
    def modifyAccessToken(self, accessToken, context):
        return True

    # context is reference of io.jans.as.server.service.external.context.ExternalUpdateTokenContext (in https://github.com/JanssenProject/jans-auth-server project, )
    def getRefreshTokenLifetimeInSeconds(self, context):
        return 0

    # context is reference of io.jans.as.server.service.external.context.ExternalUpdateTokenContext (in https://github.com/JanssenProject/jans-auth-server project, )
    def getIdTokenLifetimeInSeconds(self, context):
        return 0

    # context is reference of io.jans.as.server.service.external.context.ExternalUpdateTokenContext (in https://github.com/JanssenProject/jans-auth-server project, )
    def getAccessTokenLifetimeInSeconds(self, context):
        return 0