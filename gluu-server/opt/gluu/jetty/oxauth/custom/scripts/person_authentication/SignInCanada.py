# Sign In Canada LoA2 authentication script
#
# This script has potentially 5 steps:
#    Step 1: Detect the RP Langauge
#    Step 2: Prompt for langauage (splash page) (if language detection fails)
#    Step 3: Choose authenticaiton method (if more than one choice)
#    Step 4: Passport authentication
#    Step 5: Legacy PAI collection (if the RP is transitioning from GCCF)
#    Step 6: MFA
#
# .. however, entire steps may be skipped depending on whether they are
# required or enabled. This means the step # passed by oxAuth may not reflect
# the actual step being performed.
#
# Author: Doug Harris

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import AuthenticationService, ClientService, UserService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources, FacesService
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam
from org.gluu.oxauth.model.common import Prompt
from org.gluu.oxauth.model.util import Base64Util

from com.microsoft.applicationinsights import TelemetryClient

from java.util import Arrays

import sys
import json
import time

class SICError(Exception):
    """Base class for exceptions in this module."""
    pass

sys.path.append("/opt/gluu/jetty/oxauth/custom/scripts/person_authentication")

REMOTE_DEBUG = False

if REMOTE_DEBUG:
    try:
        sys.path.append("/opt/libs/pydevd")
        import pydevd
    except ImportError as ex:
        print ("Failed to import pydevd: %s" % ex)
        raise

from sic import passport, account, crypto

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
        
        self.name = customScript.getName()
        
        print ("%s: Initializing" % self.name)

        # Get the list of providers and parse into a set for quick membership tests
        providersParam = configurationAttributes.get("providers").getValue2()
        if providersParam is None:
            print ("%s: Providers parameter is missing from config!"  % self.name)
            return False
        else:
            self.providers = set([item.strip() for item in providersParam.split(",")])

        # Get the defaults for RP business rule & UI configuration
        defaultsParam = configurationAttributes.get("rp_defaults").getValue2()
        if defaultsParam is None:
            print ("%s: RP defaults (rp_defaults) are missing from config!" % self.name)
            return False
        else:
            try:
                self.rpDefaults = json.loads(defaultsParam)
            except ValueError:
                print ("%s: failed to parse RP defaults!" % self.name)
                return False

        # Keep an in-memory cache of RP Configs
        self.rpConfigCache = {}

        self.passport = passport.Passport()
        self.passport.init(configurationAttributes, self.name)
        
        self.account = account.Account()

        self.telemetryClient = TelemetryClient()

        print ("%s: Initialized" % self.name)
        return True

    def destroy(self, configurationAttributes):
        print ("%s: Destroyed" % self.name)
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        # Inject dependencies
        identity = CdiUtil.bean(Identity)

        client = self.getClient(identity.getSessionId())
        defaultAcrValues = client.getDefaultAcrValues()
        # If any default ACR values are explicitly configured on the client,
        # then don't allow any others
        if defaultAcrValues is None or self.name in defaultAcrValues:
            return True
        else:
            return False

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("stepCount",  # Used to extend the workflow
                             "provider",   # The provider chosen by the user
                             "abort",      # Used to trigger error abort back to the RP
                             "forceAuthn", # Used to force authentication when prompt comes with login
                             "userId",     # Used to keep track of the user across multiple passport reqiuests (i.e. collection)
                             "mfaId")      # Used to bind a 2nd factor credential into the session

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesService = CdiUtil.bean(FacesService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        externalContext = facesResources.getFacesContext().getExternalContext()
        uiLocales = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)
        abort = identity.getWorkingParameter("abort")

        externalContext.addResponseHeader("Content-Security-Policy", "default-src 'self' https://www.canada.ca; font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://www.canada.ca; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline' https://use.fontawesome.com https://fonts.googleapis.com https://www.canada.ca; script-src 'self' 'unsafe-inline' https://www.canada.ca https://ajax.googleapis.com; connect-src 'self' https://*.fjgc-gccf.gc.ca")

        if step == 1:
            facesContext = facesResources.getFacesContext()
            httpRequest = facesContext.getCurrentInstance().getExternalContext().getRequest()
            prompt2 = httpRequest.getParameter("prompt2")
            if prompt2 == "login":
                identity.setWorkingParameter("forceAuthn", True)

        if step == 1 or abort:
            # Obtain the client URI of the current client from the client configuration
            clientUri = self.getClientUri(session)
            if (clientUri is None):
                print("%s: prepareForStep. clientUri is missing for client %s" %self.name, self.getClient(session).getClientName())
                return False

        if abort:
            if len(self.providers) == 1:
                facesService.redirectToExternalURL(clientUri)
                return True
            else:
                identity.setWorkingParameter("provider", None)

        if uiLocales is None: # Language detection required
            if step == 1:
                identity.setWorkingParameter("client_uri", clientUri)
                externalContext = facesResources.getFacesContext().getExternalContext()
                externalContext.setResponseHeader("Content-Security-Policy", "connect-src 'self' " + clientUri)
            
        else: # Language is known. Check for provider
            provider = identity.getWorkingParameter("provider")
            if provider is None and len(self.providers) == 1: # Only one provider. Direct Pass-through
                provider = next(iter(self.providers))

            if provider is None:  # No provider chosen yet. Prepare for chooser page customization.
                rpConfig = self.getRPConfig(session)
                for param in ["layout", "chooser", "content"]:
                    identity.setWorkingParameter(param, rpConfig[param])

            else: # Prepare for call to passport
                passportOptions = {"ui_locales": uiLocales, "exp" : int(time.time()) + 60}
                userId = identity.getWorkingParameter("userId")
                rpConfig = self.getRPConfig(session)

                if userId is None: # This is our first request to passport
                    # Coordinate single-sign-on (SSO)
                    maxAge = (sessionAttributes.get(AuthorizeRequestParam.PROMPT)
                            or self.getClient(session).getDefaultMaxAge())
                    if (identity.getWorkingParameter("forceAuthn")
                        or ("GCCF" in self.passport.getProvider(provider)["options"] and maxAge < 1200)): # 1200 is 20 minutes, the SSO timeout on GCKey and CBS
                        passportOptions["forceAuthn"] = "true"

                elif provider != rpConfig.get("mfaProvider"): # This is our second (PAI collection) request to passport
                    collect = rpConfig.get("collect")
                    if collect is None: # This should never happen
                        print ("%s. prepareForStep: collection entityID is missing" % (self.name))
                        return False

                    passportOptions["allowCreate"] = "false"
                    passportOptions["spNameQualifier"] = collect

                else: # This is our third (mfa) reqest to passport
                    mfaId = identity.getWorkingParameter("mfaId")
                    if mfaId is None:
                        print("%s: prepareForStep. mfaId is missing!" % self.name)
                        return False
                    passportOptions["login_hint"] = mfaId
                    # The following parameters are redundant, but currently required by the 2ndFaaS
                    passportOptions["redirect_uri"] = self.passport.getProvider(provider)["callbackUrl"]
                    passportOptions["response_type"] = "code"
                    passportOptions["scope"] = "openid profile"

                # Set the abort flag so we only do this once
                identity.setWorkingParameter("abort", True)
                # Send the request to passport
                passportRequest = self.passport.createRequest(provider, passportOptions)
                facesService.redirectToExternalURL(passportRequest)

        return True
        
    def authenticate(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        facesService = CdiUtil.bean(FacesService)
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        rpConfig = self.getRPConfig(session)

        # Clear the abort flag
        identity.setWorkingParameter("abort", False)

        if ServerUtil.getFirstValue(requestParameters, "user") is not None:
            # Successful response from passport
            return self.authenticateUser(identity, languageBean, requestParameters)

        elif ServerUtil.getFirstValue(requestParameters, "failure") is not None:
            # This means that passport returned an error
            userId = identity.getWorkingParameter("userId")
            if userId is None: # User Cancelled during login
                if len(self.providers) == 1: # One provider. Redirect back to the RP
                    facesService.redirectToExternalURL(self.getClientUri(session))
                else: # Clear the previous choice to re-display the chooser
                    # locale = ServerUtil.getFirstValue(requestParameters, "ui_locale") # TODO: Update passport to send language onerror
                    # sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
                    identity.setWorkingParameter("provider", None)
            elif identity.getWorkingParameter("provider") == rpConfig.get("mfaProvider"): # MFA Failed. Redirect back to the RP
                facesService.redirectToExternalURL(self.getClientUri(session))
            else: # PAI Collection failed. If it's a SAML SP, Create a new SIC PAI
                # TODO: Check the actual SANLStatus for InvalidNameIdPolicy (needs to be sent from Passport)
                spNameQualifier = sessionAttributes.get("spNameQualifier")
                if spNameQualifier is not None:
                    user = userService.getUser(identity.getWorkingParameter("userId"), "persistentId")
                    user = self.account.addSamlSubject(user, spNameQualifier)
                    userService.updateUser(user)
                return authenticationService.authenticate(userId)

        elif ServerUtil.getFirstValue(requestParameters, "rplang") is not None:
            # Language detection result
            locale = ServerUtil.getFirstValue(requestParameters, "rplang:rplocale")
            if locale[:2].lower() in ["en", "fr"]:
                languageBean.setLocaleCode(locale)
                sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
            
        elif ServerUtil.getFirstValue(requestParameters, "lang") is not None:
            # Manually selected language
            locale = self.getFormButton(requestParameters)
            if locale in {"en-CA", "fr-CA"}:
                languageBean.setLocaleCode(locale)
                sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
            else:
                return False

        elif ServerUtil.getFirstValue(requestParameters, "chooser") is not None:
            # Chooser page
            choice = self.getFormButton(requestParameters)
            if choice == "gckeyregister": choice = "gckey" #Hack!
            if choice in self.providers:
                identity.setWorkingParameter("provider", choice)
            else:
                return False

        else: # Invalid response
            return False

        self.addAuthenticationStep()
        return True

    def authenticateUser(self, identity, languageBean, requestParameters):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()

        rpConfig = self.getRPConfig(session)

        externalProfile = self.passport.handleResponse(requestParameters)

        provider = externalProfile["provider"]
        if provider not in self.providers and provider != rpConfig.get("mfaProvider"):
            # Unauthorized provider!
            return False
        else:
            providerInfo = self.passport.getProvider(provider)

        eventProperties = {"client": self.getClient(session).getClientName(),
                           "provider": provider}

        if providerInfo["GCCF"]:
            sessionAttributes.put("authnInstant", externalProfile["authnInstant"][0])

        if identity.getWorkingParameter("userId") is None: # Initial login
            user = self.account.find(externalProfile)
            if user is None:
                user = self.account.create(externalProfile)
                newUser = True
            else:
                newUser = False
                userChanged = False
            identity.setWorkingParameter("userId", user.getUserId())

            if providerInfo["GCCF"]:
                # Capture the SAML Subject and SessionIndex for the user's IDP session.
                # We will need these later for SAML SLO.
                sessionAttributes.put("persistentId", externalProfile["persistentId"][0])
                sessionAttributes.put("sessionIndex", externalProfile["sessionIndex"][0])

            # Update the preferred language if it has changed
            locale = ServerUtil.getFirstValue(requestParameters, "locale")
            if locale:
                locale += "-CA"
                languageBean.setLocaleCode(locale)
                sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
            else: # Language cookie was blocked
                locale = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)

            if locale != user.getAttribute("locale", True, False):
                user.setAttribute("locale", locale, False)
                userChanged = True

            # If it's a SAML RP without collection enabled, then create our own PAI
            spNameQualifier = sessionAttributes.get("spNameQualifier")
            if spNameQualifier is not None and "collect" not in rpConfig and self.account.getSamlSubject(user, spNameQualifier) is None:
                user = self.account.addSamlSubject(user, spNameQualifier)
                userChanged = True

            if rpConfig.get("mfaProvider"): # IF MFA is enabled
                # grab the mfaId, or create  if needed
                mfaId = self.account.getExternalUid(user, "mfa")
                if mfaId is None:
                    mfaId = self.account.addExternalUid(user, "mfa")
                    userChanged = True
                identity.setWorkingParameter("mfaId", mfaId)

            if newUser:
                userService.addUser(user, True)
            elif userChanged:
                userService.updateUser(user)

            # Do we need to perform legacy PAI collection next? (OpenID clients only for now)
            if (providerInfo["GCCF"] and "collect" in rpConfig
                and self.account.getSamlSubject(user, rpConfig["collect"]) is None): # And we don't already have a PAI
                    # Then yes, add the collection step:
                    self.addAuthenticationStep()
                    return True
            # Do we need to perform MFA next?
            elif rpConfig.get("mfaProvider"): 
                identity.setWorkingParameter("provider", rpConfig["mfaProvider"])
                self.addAuthenticationStep()
                return True

            eventProperties["sub"] = self.account.getOpenIdSubject(user, self.getClient(session))
            self.telemetryClient.trackEvent("Authentication", eventProperties, None)

            return authenticationService.authenticate(user.getUserId())

        elif provider != rpConfig.get("mfaProvider"): # PAI Collection
            user = userService.getUser(identity.getWorkingParameter("userId"), "inum", "uid", "persistentId")
            # Validate the session first
            if externalProfile["sessionIndex"][0] != sessionAttributes.get("sessionIndex"):
                print ("%s: IDP session missmatch during PAI collection for user %s."
                        % (self.name, identity.getWorkingParameter("userId")))
                return False

            collect = rpConfig.get("collect")
            if collect is None: # This should never happen
                print ("%s. authenticateUser: collection entityID is missing" % (self.name))
                return False

            # Collect the SAML PAI
            spNameQualifier, nameQualifier, nameId = tuple(externalProfile["persistentId"][0].split("|"))
            if spNameQualifier == "undefined":
                spNameQualifier = collect
            if nameQualifier == "undefined":
                nameQualifier = externalProfile["issuer"][0]
            if not self.account.getSamlSubject(user, spNameQualifier): # unless one already exists
                user = self.account.addSamlSubject(user, spNameQualifier, nameQualifier, nameId)
            userService.updateUser(user)

            # construct an OIDC pairwise subject using the SAML PAI
            client = self.getClient(session)
            if not self.account.getOpenIdSubject(user, client): # unless one already exists
                self.account.addOpenIdSubject(user, client, provider + nameId)

            # Is MFA required next?
            if rpConfig.get("mfaProvider"):
                identity.setWorkingParameter("provider", rpConfig["mfaProvider"])
                self.addAuthenticationStep()
                return True

            eventProperties["sub"] = self.account.getOpenIdSubject(user, self.getClient(session))
            self.telemetryClient.trackEvent("Authentication", eventProperties, None)
            return authenticationService.authenticate(user.getUserId())

        else: # MFA
            user = userService.getUser(identity.getWorkingParameter("userId"), "uid", "oxExternalUid", "locale")
            mfaExternalId = self.account.getExternalUid(user, "mfa")
            if externalProfile.get("externalUid").split(":", 1)[1] != mfaExternalId:
                # Got the wrong MFA PAI. Authentication failed!
                return False

            # Accept locale from the 2nd-factor CSP
            locale = externalProfile.get("locale")[0]
            if locale:
                languageBean.setLocaleCode(locale)
                if locale != user.getAttribute("locale", True, False):
                    user.setAttribute("locale", locale, False)
                    userService.updateUser(user)

            eventProperties["sub"] = self.account.getOpenIdSubject(user, self.getClient(session))
            self.telemetryClient.trackEvent("Authentication", eventProperties, None)
            return authenticationService.authenticate(user.getUserId())

    def getPageForStep(self, configurationAttributes, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)

        session = identity.getSessionId()

        # Check for ui_locales
        uiLocales = None
        if session is None: # No session yet
            facesContext = facesResources.getFacesContext()
            httpRequest = facesContext.getCurrentInstance().getExternalContext().getRequest()
            uiLocales = httpRequest.getParameter(AuthorizeRequestParam.UI_LOCALES)
        else:
            # Session exists.
            uiLocales = session.getSessionAttributes().get(AuthorizeRequestParam.UI_LOCALES)

        if uiLocales is None:
            if step == 1: # Language detection
                return "/detlang.xhtml"
            elif step == 2: # Language Selection (Splash Page)
                return "/lang.xhtml"

        elif len(self.providers) > 1 and identity.getWorkingParameter("provider") is None:
            # Chooser page
            language = uiLocales[:2].lower()
            if language == "fr":
                return "/fr/choisir.xhtml"
            else:
                return "/en/select.xhtml"

        # Otherwise, clear the abort flag and invoke Passport
        identity.getWorkingParameters().remove("abort")
        return "/auth/passport/passportlogin.xhtml"

    def addAuthenticationStep(self):
        identity = CdiUtil.bean(Identity)
        stepCount = identity.getWorkingParameter("stepCount")
        if stepCount is None:
            identity.setWorkingParameter("stepCount", 2)
        else:
            identity.setWorkingParameter("stepCount", stepCount + 1)

    def getCountAuthenticationSteps(self, configurationAttributes):
        identity = CdiUtil.bean(Identity)
        stepCount = identity.getWorkingParameter("stepCount")
        
        if stepCount is None:
            return 1
        else:
            return stepCount
 
    def getNextStep(self, configurationAttributes, requestParameters, step):
        identity = CdiUtil.bean(Identity)
        nextStep = identity.getWorkingParameter("nextStep")
        
        if nextStep is None:
            return -1
        else:
            identity.setWorkingParameter("nextStep", None)
            return nextStep


    ### Form response parsing
    def getFormButton(self, requestParameters):
        for parameter in requestParameters.keySet():
            start = parameter.find(":")
            if start > -1:
                return parameter[start + 1:]

    ### Client Config Utilities

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
        client = self.getClient(session)

        # check the cache
        clientKey = "oidc:%s" % client.getClientId()
        if clientKey in self.rpConfigCache:
            return self.rpConfigCache[clientKey]

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
        self.rpConfigCache[clientKey] = rpConfig
        return rpConfig
