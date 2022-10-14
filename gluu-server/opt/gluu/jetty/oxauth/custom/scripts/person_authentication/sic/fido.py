# Module for FIDO2 / WebAuthn
#
# Author: Doug Harris

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, ClientService, UserService
from org.gluu.fido2.client import Fido2ClientFactory
from org.gluu.model import GluuStatus

from javax.ws.rs.core import Response
from javax.ws.rs import ClientErrorException
from java.util.concurrent.locks import ReentrantLock

from com.microsoft.applicationinsights import TelemetryClient

import sys
import java
import json

class FidoError(Exception):
    """Base class for exceptions in this module."""
    pass

class Fido:

    def __init__(self):
        return None
    
    def init(self, configurationAttributes, scriptName):

        self.scriptName = scriptName
        print ("FIDO. init called from " + self.scriptName)

        self.fido2_server_uri = configurationAttributes.get("fido2_server_uri").getValue2()
        self.fido2_domain = None
        if configurationAttributes.containsKey("fido2_domain"):
            self.fido2_domain = configurationAttributes.get("fido2_domain").getValue2()

        self.telemetryClient = TelemetryClient()
        self.metaDataLoaderLock = ReentrantLock()
        self.fidoMetaDataConfiguration = None

    def generateAttestationRequest (self, userId):
        metaDataConfiguration = self.getFidoMetaDataConfiguration()

        try:
            attestationService = Fido2ClientFactory.instance().createAttestationService(metaDataConfiguration)
            userService = CdiUtil.bean(UserService)
            user = userService.getUser(userId, "displayName")
            attestationRequest = json.dumps({'username': userId,
                                             'displayName': userId,
                                             'attestation' : 'direct'
                                            }, separators=(',', ':'))
            attestationResponse = attestationService.register(attestationRequest).readEntity(java.lang.String)
            tmp = json.loads(attestationResponse)
            tmp.pop("authenticatorSelection", None)
            tmp['authenticatorSelection'] = {'userVerification': 'required',
                                             'residentKey': 'required',
                                             'requireResidentKey': True
                                             }
            attestationResponse = json.dumps(tmp, separators=(',', ':'))
        except ClientErrorException as ex:
            print ("%s. generate Attestation Request. Failed to start FIDO2 attestation flow. Exception:" % self.scriptName, sys.exc_info()[1])
            return None
        return ServerUtil.asJson(attestationResponse)

    def generateAssertionRequest (self, userId):
        metaDataConfiguration = self.getFidoMetaDataConfiguration()
        userService = CdiUtil.bean(UserService)

        fidoDeviceCount = userService.countFidoAndFido2Devices(userId, self.fido2_domain)
        try:
            assertionService = Fido2ClientFactory.instance().createAssertionService(metaDataConfiguration)
            assertionRequest = json.dumps({'username': userId, 'timeout': 120000, 'userVerification': 'required'}, separators=(',', ':'))
            assertionResponse = assertionService.authenticate(assertionRequest).readEntity(java.lang.String)
        except ClientErrorException as ex:
            print ("%s. Generate Assertion Request. Failed to start FIDO2 assertion flow. Exception:" %self.scriptName, sys.exc_info()[1])
            return None
        return ServerUtil.asJson(assertionResponse)

    def registerFido2(self, tokenResponse):
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)

        metaDataConfiguration = self.getFidoMetaDataConfiguration()
        attestationService = Fido2ClientFactory.instance().createAttestationService(metaDataConfiguration)
        attestationStatus = attestationService.verify(tokenResponse)

        if attestationStatus.getStatus() != Response.Status.OK.getStatusCode():
            print ("%s. register FIDO2. Got invalid registration status from Fido2 server" % self.scriptName)
            return False
        username = identity.getWorkingParameter("userId")
        userService.replaceUserAttribute(username, "gluuStatus", GluuStatus.REGISTER.getValue(), GluuStatus.ACTIVE.getValue())

        print ("%s. register FIDO2. Sucessfully registered %s" % (self.scriptName, username))
        return authenticationService.authenticate(username)

    def authenticateFido2(self, tokenResponse):
        authenticationService = CdiUtil.bean(AuthenticationService)

        metaDataConfiguration = self.getFidoMetaDataConfiguration()
        assertionService = Fido2ClientFactory.instance().createAssertionService(metaDataConfiguration)
        assertionStatus = assertionService.verify(tokenResponse)
        authenticationResult = json.loads(assertionStatus.readEntity(java.lang.String))

        if assertionStatus.getStatus() != Response.Status.OK.getStatusCode():
            print ("%s. Authenticate FIDO2. Got invalid authentication status from Fido2 server" % self.scriptName)
            return False

        return authenticationService.authenticate(authenticationResult["username"])

    # FIDO2 Metadata loading
    # This is deferred so that the FIDO2 service has time to start
    def getFidoMetaDataConfiguration(self):
        if self.fidoMetaDataConfiguration != None:
            return self.fidoMetaDataConfiguration
        
        self.metaDataLoaderLock.lock()
        # Make sure that another thread not loaded configuration already
        if self.fidoMetaDataConfiguration != None:
            return self.fidoMetaDataConfiguration

        try:
            print ("%s. Initialization. Downloading Fido2 metadata" % self.scriptName)
            self.fido2_server_metadata_uri = self.fido2_server_uri + "/.well-known/fido2-configuration"

            metaDataConfigurationService = Fido2ClientFactory.instance().createMetaDataConfigurationService(self.fido2_server_metadata_uri)
    
            max_attempts = 10
            for attempt in range(1, max_attempts + 1):
                try:
                    self.fidoMetaDataConfiguration = metaDataConfigurationService.getMetadataConfiguration().readEntity(java.lang.String)
                    return self.fidoMetaDataConfiguration
                except ClientErrorException as ex:
                    # Detect if last try or we still get Service Unavailable HTTP error
                    if (attempt == max_attempts) or (ex.getResponse().getResponseStatus() != Response.Status.SERVICE_UNAVAILABLE):
                        raise ex
    
                    java.lang.Thread.sleep(3000)
                    print ("Attempting to load metadata: %d" % attempt)
        finally:
            self.metaDataLoaderLock.unlock()
