# Module for interacting with gluu_passport
#
# Author: Doug Harris

from org.gluu.jsf2.service import FacesService

from org.gluu.oxauth.model.common import User, WebKeyStorage
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.model.crypto import CryptoProviderFactory
from org.gluu.oxauth.model.jwt import Jwt, JwtClaimName
from org.gluu.oxauth.service.common import EncryptionService
from org.gluu.oxauth.service.net import HttpService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.config.oxtrust import LdapOxPassportConfiguration
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper

from java.util import Collections
from javax.faces.context import FacesContext
from java.net import URLEncoder
from org.apache.commons.lang3 import StringUtils

from com.microsoft.applicationinsights import TelemetryClient

import json
import sys
import datetime

class PassportError(Exception):
    """Base class for exceptions in this module."""
    pass

class Passport:
    """Integration with passport for inbound authentication (acceptance)."""
    def __init__(self):
        return None

    def init(self, configurationAttributes, scriptName):

        print ("Passport. init called from " + scriptName)

        self.telemetryClient = TelemetryClient()

        try:
            # Instantiate a Crypto Provider to verify token signatures
            self.keyStoreFile = configurationAttributes.get("key_store_file").getValue2()
            self.keyStorePassword = configurationAttributes.get("key_store_password").getValue2()

            appConfiguration = AppConfiguration()
            appConfiguration.setWebKeysStorage(WebKeyStorage.KEYSTORE)
            appConfiguration.setKeyStoreFile(self.keyStoreFile)
            appConfiguration.setKeyStoreSecret(self.keyStorePassword)
            appConfiguration.setRejectJwtWithNoneAlg(True)
            appConfiguration.setKeyRegenerationEnabled(False)

            self.cryptoProvider = CryptoProviderFactory.getCryptoProvider(appConfiguration)

            # Load the passport config
            with open('/etc/gluu/conf/passport-config.json', 'r') as configFile:
                self.passportConfig = json.load(configFile)
                if StringHelper.isEmpty(self.passportConfig["keyAlg"]) or StringHelper.isEmpty(self.passportConfig["keyId"]):
                    print ("Passport. init for %s. Failed to read key information from passport-config" % scriptName)
                    return False

            # Load all provider configurations
            self.registeredProviders = self.parseProviders()

        except:
            print ("Passport. init for %s. Initialization failed:" % scriptName)
            print (sys.exc_info())
            return False

        print ("Passport. init for %s. Initialization success" % scriptName)
        return True

    def createRequest(self, providerId, params):
        """Create a redirect  URL to send an authentication request to passport."""

        url = None
        try:
            providerConfig = self.registeredProviders.get(providerId)
            if providerConfig is None:
                print ("Passport. createRequest. Provider %s does not exist" % providerId)
                raise PassportError()

            facesContext = CdiUtil.bean(FacesContext)
            serverName = facesContext.getExternalContext().getRequest().getServerName()
            tokenEndpoint = "https://%s/passport/token" % serverName
            
            httpService = CdiUtil.bean(HttpService)
            httpclient = httpService.getHttpsClient()
            resultResponse = httpService.executeGet(httpclient, tokenEndpoint, Collections.singletonMap("Accept", "text/json"))
            httpResponse = resultResponse.getHttpResponse()
            bytes = httpService.getResponseContent(httpResponse)
            response = httpService.convertEntityToString(bytes)
            if response is not None:
                token = json.loads(response)["token_"]
            else:
                raise PassportError("Failed to obtain token from Passport")

            if params is not None:
                jsonParams = json.dumps(params)
                encryptedParams = CdiUtil.bean(EncryptionService).encrypt(jsonParams)
                # Need to translate from base64 to base64url to make it URL-friendly for passport
                # See RFC4648 section 5
                encodedParams = StringUtils.replaceChars(encryptedParams, "/+", "_-")

                url = "/passport/auth/%s/%s/%s" % (providerId, token, encodedParams)
                if providerConfig["GCCF"]:
                    # Need to set the language cookie
                    langCode = {"en": "eng", "fr": "fra"}[params["ui_locales"][:2].lower()]
                    url = "%s?lang=%s&return=%s" % (self.passportConfig["languageCookieService"], langCode,
                                            URLEncoder.encode("https://" + serverName + url, "UTF8"))
            else:
                url = "/passport/auth/%s/%s" % (providerId, token)

        except:
            print ("Passport. createRequest. Error building redirect URL: ", sys.exc_info()[1])

        return url

    def handleResponse(self, requestParameters):
        """Process an authentication response from passport. Returns a User object, or None in case of failure."""

        jwt = None
        externalProfile = None
        try:
            # gets jwt parameter "user" sent after authentication by passport (if exists)
            jwt_param = ServerUtil.getFirstValue(requestParameters, "user")

            # Parse JWT and validate
            # TODO: Log a security event whenever JWT validation fails
            jwt = Jwt.parse(jwt_param)
            if not self.verifySignature(jwt):
                return None
            if self.jwtHasExpired(jwt):
                return None

            claims = jwt.getClaims()
            externalProfileJson = CdiUtil.bean(EncryptionService).decrypt(claims.getClaimAsString("data"))
            externalProfile = json.loads(externalProfileJson)

            providerId = externalProfile["provider"]
            providerConfig = self.registeredProviders.get(providerId)
            providerType = providerConfig["type"]
            
            sub = claims.getClaimAsString("sub")
            if providerType == "saml": # This is silly. It should be consistent.
                externalProfile["externalUid"] = "passport-saml:%s:%s" % (providerId, sub)
            else:
                externalProfile["externalUid"] = "passport-%s:%s" % (providerId, sub)

        except:
            print ("Passport. handleResponse. Invalid JWT from passport")
            return None

        return externalProfile

    def getProvider(self, providerId):
        """Get the configuration info for a provider"""
        return self.registeredProviders.get(providerId)

# Initialization routines

    def processKeyStoreProperties(self, attrs):
        file = attrs.get("key_store_file")
        password = attrs.get("key_store_password")

        if file != None and password != None:
            file = file.getValue2()
            password = password.getValue2()

            if StringHelper.isNotEmpty(file) and StringHelper.isNotEmpty(password):
                self.keyStoreFile = file
                self.keyStorePassword = password
                return True

        print ("Passport. readKeyStoreProperties. Properties key_store_file or key_store_password not found or empty")
        return False

# Configuration parsing

    def getPassportConfigDN(self):

        f = open('/etc/gluu/conf/gluu.properties', 'r')
        for line in f:
            prop = line.split("=")
            if prop[0] == "oxpassport_ConfigurationEntryDN":
                prop.pop(0)
                break

        f.close()
        return "=".join(prop).strip()

    def parseProviders(self):
        print ("Passport. parseProviders. Adding providers")

        registeredProviders = {}

        entryManager = CdiUtil.bean(PersistenceEntryManager)

        config = LdapOxPassportConfiguration()
        passportDN = self.getPassportConfigDN()

        passportConfig = entryManager.find(config.getClass(), passportDN).getPassportConfiguration()
        
        if passportConfig is None:
            print("Passport. parseProviders. Failed to retrieve the passport configuration")
            return None
        
        providers = passportConfig.getProviders()

        if providers is not None and len(providers) > 0:
            for provider in providers:
                if provider.isEnabled():
                    registeredProviders[provider.getId()] = {
                        "type": provider.getType(),
                        "options": provider.getOptions(),
                        "GCCF": "GCCF" in provider.getOptions() and provider.getOptions()["GCCF"].lower() in ["true", "yes"],
                        "callbackUrl": provider.getCallbackUrl()
                    }
                    print("Configured %s provider %s" % (provider.getType(), provider.getId()))

        return registeredProviders

# Token verification

    def verifySignature(self, jwt):

        # Fail safely
        valid = False

        try:
            algName = jwt.getHeader().getSignatureAlgorithm().getName()
            keyId = jwt.getHeader().getKeyId()
            signature = jwt.getEncodedSignature()

            if StringHelper.isEmpty(algName) or algName != self.passportConfig["keyAlg"]:
                message = "Passport JWT signature algorithm does not match passport configuration"
                self.telemetryClient.trackEvent("SecurityEvent",
                                                {"cause": message,
                                                 "expected": self.passportConfig["keyAlg"],
                                                 "got" : algName}, None)
                print ("SECURITY: %s" % message)
                return False

            if keyId != self.passportConfig["keyId"]:
                message = "Passport JWT not signed with the passport key"
                self.telemetryClient.trackEvent("SecurityEvent",
                                                {"cause": message,
                                                 "expected": self.passportConfig["keyId"],
                                                 "got" : keyId}, None)
                print ("SECURITY: %s" % message)
                return False

            if StringHelper.isEmpty(signature):
                # blocks empty signature string
                message = "Passport JWT signature missing"
                self.telemetryClient.trackEvent("SecurityEvent",
                                                {"cause": message}, None)
                print ("SECURITY: %s" % message)
                return False

            else:
                valid = self.cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), jwt.getHeader().getKeyId(),
                                                            None, None, jwt.getHeader().getSignatureAlgorithm())
                if not valid:
                    message = "Passport JWT signature failed validation"
                    self.telemetryClient.trackEvent("SecurityEvent",
                                                    {"cause": message}, None)
                    print ("SECURITY: %s" % message)

        except:
            message = "Passport JWT validation Exception: " + sys.exc_info()[1]
            self.telemetryClient.trackEvent("SecurityEvent",
                                            {"cause": message}, None)
            print ("SECURITY: %s" % message)

        return valid

    def jwtHasExpired(self, jwt):
        # Check if jwt has expired
        hasExpired = False

        jwt_claims = jwt.getClaims()
        try:
            exp_date_timestamp = float(jwt_claims.getClaimAsString(JwtClaimName.EXPIRATION_TIME))
            exp_date = datetime.datetime.fromtimestamp(exp_date_timestamp)
            hasExpired = exp_date < datetime.datetime.now()
        except:
            print ("Exception: The JWT does not have a valid '%s' attribute" % JwtClaimName.EXPIRATION_TIME)

        if hasExpired:
            message = "Passport JWT has expired; Possible token replay."
            self.telemetryClient.trackEvent("SecurityEvent",
                                            {"cause": message,
                                             "exp" : jwt_claims.getClaimAsString(JwtClaimName.EXPIRATION_TIME)}, None)
            print ("SECURITY: %s" % message)

        return hasExpired
