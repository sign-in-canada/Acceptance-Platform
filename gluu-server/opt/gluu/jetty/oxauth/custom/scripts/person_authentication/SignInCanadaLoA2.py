# Sign In Canada LoA2 authentication script
#
# This script has potentially 4 steps:
#    Step 1: Detect the RP Langauge
#    Step 2: Prompt for langauage (splash page) (if language detection fails)
#    Step 3: Choose authenticaiton method (if more than one choice)
#    Step 4: Passport authentication
#    Step 5: Legacy PAI collection (if the RP is transitioning from GCCF)
#
# .. however, entire steps may be skipped depending on whether they are
# required or enabled. This means the step # passed by oxAuth may not reflect
# the actual step being performed.
#
# Author: Doug Harris

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import AuthenticationService, ClientService
from org.gluu.oxauth.service.common import UserService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources, FacesService
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam

from java.util import Arrays

import sys
import json

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

from sic import passport, account

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
        self.passport.init(configurationAttributes, self.name, self.providers)
        
        self.account = account.Account()

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
        return Arrays.asList("stepCount", # Used to extend the workflow
                             "provider",  # The provider chosen by the user
                             "abort")     # Used to trigger error abort back to the RP

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesService = CdiUtil.bean(FacesService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()

        uiLocales = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)
        abort = identity.getWorkingParameter("abort")

        if step == 1 or abort:
            # Obtain the client URI of the current client from the client configuration
            clientUri = self.getClientUri(session)
            if (clientUri is None):
                print("%s: clientUri is missing for client %s" %self.name, self.getClient(session).getClientName())
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
                externalContext.addResponseHeader("Content-Security-Policy", "connect-src 'self' " + clientUri)
            
        else: # Language is known. Check for provder
            provider = None
            if len(self.providers) == 1: # Only one provider. Direct Pass-through
                provider = next(iter(self.providers))
            else: # Has the user chosen?
                provider = identity.getWorkingParameter("provider")

            if provider is not None: 
                # Set the abort flag so we only do this once
                identity.setWorkingParameter("abort", True)
                # TODO: Add collection function here by testing for legacy entityId
                passportRequest = self.passport.createRequest(provider, uiLocales, None)
                facesService.redirectToExternalURL(passportRequest)
            else: # No provider chosen yet. Prepare for chooser page customization.
                rpConfig = self.getRPConfig(session)
                for param in ["layout", "chooser", "content"]:
                    identity.setWorkingParameter(param, rpConfig[param])

        return True
        
    def authenticate(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        facesService = CdiUtil.bean(FacesService)
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()

         # Clear the abort flag
        identity.setWorkingParameter("abort", False)

        if ServerUtil.getFirstValue(requestParameters, "user") is not None:
            # Successful response from passport
            externalProfile = self.passport.handleResponse(requestParameters)
            if externalProfile["provider"] not in self.providers:
                # Unauthorized provider!
                return False

            user = self.account.find(externalProfile)
            if user is None:
                user = self.account.create(externalProfile)
                newUser = True
            else:
                newUser = False
                userChanged = False

            # Create a new SAML Subject if needed
            spNameQualifier = sessionAttributes.get("spNameQualifier")
            if spNameQualifier is not None and self.account.getSamlSubject(user, spNameQualifier) is None:
                user = self.account.addSamlSubject(user, spNameQualifier)
                userChanged = True

            # Update the preferred language if it has changed
            locale = ServerUtil.getFirstValue(requestParameters, "ui_locale") # TODO: change to ui_locales (needs to be done in Passport too)
            languageBean.setLocaleCode(locale)
            if locale != user.getAttribute("locale", True, False):
                user.setAttribute("locale", locale, False)
                userChanged = True

            if newUser:
                userService.createUser(user, True)
            elif userChanged:
                userService.updateUser(user)

            return authenticationService.authenticate(user.getUserId())

        elif ServerUtil.getFirstValue(requestParameters, "failure") is not None:
            # This means that passport returned an error (user probably clicked "cancel")
            if len(self.providers) == 1: # One provider. Redirect back to the RP
                facesService.redirectToExternalURL(self.getClientUri(session))
            else: # Clear the previous choice to re-display the chooser
                # locale = ServerUtil.getFirstValue(requestParameters, "ui_locale") # TODO: Update passport to send language onerror
                # sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
                identity.setWorkingParameter("provider", None)

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
                # The missing file extension below is intentional.
                # This forces an extra redirect so that the request URL matches a rule in the
                # Apache config that allows pass-through of the content security policy header.
                return "/detlang"
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
            clientUri = sessionAttributes.get("spNameQualifier") # Hack!

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
                    rpConfig, index = decoder.raw_decode(description[start:])
                except ValueError:
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
