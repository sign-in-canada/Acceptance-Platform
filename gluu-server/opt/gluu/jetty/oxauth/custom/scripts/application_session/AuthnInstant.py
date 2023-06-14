# Script to synchronize the local Gluu authentication timestamp
# With that of a GCCF SAML IDP
#
# Author: Doug Harris
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.model.custom.script.type.session import ApplicationSessionType
from org.gluu.oxauth.service import SessionIdService
from org.gluu.oxauth.service.external import ExternalAuthenticationService

from java.util import Date
from java.time import Instant
from java.lang import Long

class ApplicationSession(ApplicationSessionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print ("%s: init" % customScript.getName())
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 11

    def startSession(self, httpRequest, session, configurationAttributes):
        externalAuthenticationService = CdiUtil.bean(ExternalAuthenticationService)
        sessionAttributes = session.getSessionAttributes()
        # Exponse the session expiry timestamp to Passport via the session status API
        sessionAttributes.put(SessionIdService.SESSION_CUSTOM_STATE, Long.toString(session.getExpirationDate().getTime()))

        # If no MFA for this session, use the CSP's authentication instant as our own
        # All MFA workflows are defined with an authentication level > 50
        # See https://github.com/sign-in-canada/Acceptance-Platform/blob/main/gluu-server/opt/dist/signincanada/ldif/sic-scripts.ldif
        MFA_THRESHOLD = 50

        sessionAcr = sessionAttributes.get("acr")
        acrLevels = externalAuthenticationService.acrToLevelMapping()
        authnInstant = sessionAttributes.get("authnInstant")
        if acrLevels[sessionAcr] <= MFA_THRESHOLD and authnInstant:
            session.setAuthenticationTime(Date.from(Instant.parse(authnInstant)))
        return True

    def onEvent(self, event):
        return

    def endSession(self, httpRequest, sessionId, configurationAttributes):
        return True
