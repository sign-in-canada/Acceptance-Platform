### Client Config Utilities

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.service import LocalCacheService
from org.gluu.oxauth.service import ClientService
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam

import sys, json

class RPUtils:

    def __init__(self):
        return None
    
    def init(self, configurationAttributes, scriptName):

        self.scriptName = scriptName
        print ("RPUtils. init called from " + self.scriptName)
        # Get the defaults for RP business rule & UI configuration
        defaultsParam = configurationAttributes.get("rp_defaults").getValue2()
        if defaultsParam is None:
            print ("%s: RP defaults (rp_defaults) are missing from config!" % self.name)
            return False
        else:
            try:
                self.rpDefaults = json.loads(defaultsParam)
                print ("RPUtils. defaults loaded for " + self.scriptName)
            except ValueError:
                print ("%s: failed to parse RP defaults!" % self.name)
                return False

    def getClient(self, session):
        sessionAttributes = session.getSessionAttributes()
        clientId = sessionAttributes.get(AuthorizeRequestParam.CLIENT_ID)
        return CdiUtil.bean(ClientService).getClient(clientId)

    def getClientUri(self, session):

        clientUri = self.getClient(session).getClientUri()
        if clientUri is None:
            sessionAttributes = session.getSessionAttributes()
            clientUri = sessionAttributes.get("entityId") # Hack!

        return clientUri

    def getRPConfig(self, session):
        clientService = CdiUtil.bean(ClientService)
        cacheService = CdiUtil.bean(LocalCacheService)
        client = self.getClient(session)

        # check the cache
        clientKey = "rp:oidc:%s" % client.getClientId()
        rpConfig = cacheService.get(clientKey)
        #if rpConfig:
        #    return rpConfig

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
                    pass

        if rpConfig is None:
            rpConfig = self.rpDefaults
        else: # Populate missing settings with defaults
            for setting, value in self.rpDefaults.items():
                if not setting in rpConfig:
                    rpConfig[setting] = value

        # Add it to the cache
        cacheService.put(clientKey, rpConfig)
        return rpConfig
