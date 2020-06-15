# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Doug Harris
#

from org.gluu.model.custom.script.type.session import ApplicationSessionType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import SessionIdService

import uuid

class ApplicationSession(ApplicationSessionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 2

    def startSession(self, httpRequest, sessionId, configurationAttributes):
        sessionService = CdiUtil.bean(SessionIdService)

        # Remove session from the cache
        sessionService.remove(sessionId)
        # Change the Session ID value to thwart session fixation attacks
        sessionId.setId(str(uuid.uuid4()))
        sessionId.setDn(sessionId.getId())
        # Put it back in the cache
        sessionService.updateSessionId(sessionId)
        
        return True

    def endSession(self, httpRequest, sessionId, configurationAttributes):
        return True
