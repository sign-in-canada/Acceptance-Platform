# Sign In Canada DirectLoA2 authentication script
#
# This script bypasses the user interface and authenticates directly
# with the provider specified in the config parameters.
#
# Author: Doug Harris

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import AuthenticationService, ClientService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources, FacesService
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam

from java.util import Arrays

import sys

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
        
        print ("LoA2 Direct: Initializing")

        self.passport = passport.Passport()
        self.passport.init(configurationAttributes)
        
        self.account = account.Account()
        
        self.provider = configurationAttributes.get("provider").getValue2()

        print ("LoA2 Direct: Initialized")
        return True

    def destroy(self, configurationAttributes):
        print ("LoA2 Direct: Destroyed")
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):

        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):

        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):

        return None

    def getExtraParametersForStep(self, configurationAttributes, step):

        return Arrays.asList("client_uri", "stepCount")

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesService = CdiUtil.bean(FacesService)
        clientService = CdiUtil.bean(ClientService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        
        # Obtain the client URI of the current client from the client configuration
        clientUri = identity.getWorkingParameter("client_uri")
        if clientUri is None:
            clientId = sessionAttributes.get(AuthorizeRequestParam.CLIENT_ID)
            client = clientService.getClient(clientId)
            clientUri = client.getClientUri()
            if (clientUri is None):
                print("LoA2 Direct: clientUri is missing for client " + client.getClientName())
                return False
            else:
                identity.setWorkingParameter("client_uri", clientUri)
       
        uiLocales = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)
        
        if ServerUtil.getFirstValue(requestParameters, "failure") is not None:
            # This means that passport returned an error (user probably clicked "cancel")
            # This should be implemented in authenticate, not here but that requires modifying passport in
            # a way that will break the old script.
            facesService.redirectToExternalURL(clientUri)
            
        elif uiLocales is not None: # Language detection not required
            passportRequest = self.passport.createRequest(self.provider, uiLocales, None)
            facesService.redirectToExternalURL(passportRequest)
        
        else:
            # Add the RP Site to the Content Security Policy
            externalContext = facesResources.getFacesContext().getExternalContext()
            externalContext.addResponseHeader("Content-Security-Policy", "connect-src 'self' " + clientUri)
            # TODO: Also get the RP page content settings to support multiple detection mechanisms
       
        return True
        
    def authenticate(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        authenticationService = CdiUtil.bean(AuthenticationService)
        facesService = CdiUtil.bean(FacesService)
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()

        if ServerUtil.getFirstValue(requestParameters, "user") is not None:
            # Successful response from passport
            locale = ServerUtil.getFirstValue(requestParameters, "ui_locale")
            languageBean.setLocaleCode(locale)
            
            externalProfile = self.passport.handleResponse(requestParameters)
            user = self.account.find(externalProfile)
            if user is None:
                user = self.account.create(externalProfile)
            return authenticationService.authenticate(user.getUserId())

        elif ServerUtil.getFirstValue(requestParameters, "rplang") is not None:
            # Language detection result
            locale = ServerUtil.getFirstValue(requestParameters, "rplang:rplocale")
            if locale[:2].lower() in ["en", "fr"]:
                languageBean.setLocaleCode(locale)
                sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
                identity.setWorkingParameter("stepCount", 2)
            else:
                # Detection failed. Splash page needed
                identity.setWorkingParameter("stepCount", 3)
            return True
            
        elif ServerUtil.getFirstValue(requestParameters, "lang") is not None:
            # Manually selected language
            if (ServerUtil.getFirstValue(requestParameters, "lang:English") is not None):
                locale = "en-CA"
            elif (ServerUtil.getFirstValue(requestParameters, "lang:Francais") is not None):
                locale = "fr-CA"
            else:
                return False
            
            languageBean.setLocaleCode(locale)
            sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)

        else:
            # Error. Try to send them back to the RP
            clientUri = identity.getWorkingParameter("client_uri")
            if clientUri is not None:
                facesService.redirectToExternalURL(clientUri)
            else:
                return False

        return True

    def getPageForStep(self, configurationAttributes, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)

        # Language Handling
        uiLocales = None
        
        session = identity.getSessionId()
        if session is None: # No session yet
            facesContext = facesResources.getFacesContext()
            httpRequest = facesContext.getCurrentInstance().getExternalContext().getRequest()
            uiLocales = httpRequest.getParameter(AuthorizeRequestParam.UI_LOCALES)
        else:
            # Session exists.
            uiLocales = session.getSessionAttributes().get(AuthorizeRequestParam.UI_LOCALES)

        if uiLocales is None:
            if step == 1:
                # The missing file extension below is intentional.
                # This forces an extra redirect so that the request URL matches a rule in the
                # Apache config that allows pass-through of the content security policy header.
                return "/detlang"
            elif step == 2:
                return "/lang.xhtml"
        else:
            # Language determined. Invoke passport
            return "/auth/passport/passportlogin.xhtml"


    def getCountAuthenticationSteps(self, configurationAttributes):
        identity = CdiUtil.bean(Identity)
        stepCount = identity.getWorkingParameter("stepCount")
        
        if stepCount is None:
            return 1
        else:
            return stepCount
 
    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1
