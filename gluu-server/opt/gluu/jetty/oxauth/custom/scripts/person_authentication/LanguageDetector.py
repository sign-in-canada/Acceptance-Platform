# Determines the useer's preferred session language if the RP did not
# provide ui_locales in the authentication request.
#
# Step 1: Attempt to detect the language via some mechanism
# Step 2: If unable to detect, put up a splash page
#

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import ClientService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources

from java.util import Arrays

import json

REMOTE_DEBUG = False

if REMOTE_DEBUG:
    try:
        import sys
        sys.path.append("/opt/libs/pydevd")
        import pydevd
    except ImportError as ex:
        print ("Failed to import pydevd: %s" % ex)
        raise

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print ("LanguageDetector: Initializing")

        print ("LanguageDetector init: Load RP customization file.")
        if not configurationAttributes.containsKey("selector_page_content_file"):
            print ("LanguageDetector: Initialization Failed, RP customization file parameter 'selector_page_content_file' missing.")
            return False

        content_file = configurationAttributes.get("selector_page_content_file").getValue2()

        # Load customization content from file
        f = open(content_file, 'r')
        try:
            self.selectorPageContent = json.loads(f.read())
        except:
            print ("LanguageDetector Initialization. Failed to load RP customization content from file: %s" % content_file)
            return False
        finally:
            f.close()

        print ("LanguageDetector: Initialized")
        return True

    def destroy(self, configurationAttributes):
        print ("LanguageDetector: Destroyed")
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)

        detectedLocale = identity.getWorkingParameter("detectedLocale")

        if (detectedLocale is None):
            return True
        else:
            return False

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        return "select_loa2"

    def getExtraParametersForStep(self, configurationAttributes, step):

        return Arrays.asList("detectedLocale")

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)


        if (step > 1):
            # No need to prepare anything for the chooser page
            return True

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        clientService = CdiUtil.bean(ClientService)
        facesResources = CdiUtil.bean(FacesResources)

        # Obtain the client URI of the current client from the client configuration
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        clientId = sessionAttributes.get("client_id")
        client = clientService.getClient(clientId)
        clientUri = client.getClientUri()

        # Make it available to the language detection page
        identity.setWorkingParameter("client_uri", clientUri)

        # Add the RP Site to the Content Security Policy
        externalContext = facesResources.getFacesContext().getExternalContext()
        externalContext.addResponseHeader("Content-Security-Policy", "connect-src 'self' " + clientUri)

        # TODO: Also get the RP page content settings to support multiple detection mechanisms
        
        return True
        
    def authenticate(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)

        locale = None

        if (ServerUtil.getFirstValue(requestParameters, "rplang") is not None):
            locale = ServerUtil.getFirstValue(requestParameters, "rplang:rplocale")
            
        elif (ServerUtil.getFirstValue(requestParameters, "lang") is not None):
            if (ServerUtil.getFirstValue(requestParameters, "lang:English") is not None):
                locale = "en-CA"
            elif (ServerUtil.getFirstValue(requestParameters, "lang:Francais") is not None):
                locale = "fr-CA"
            else:
                return False

        if (locale is not None):
            language = locale[:2].lower()
            if (language == "en" or language == "fr"):
                languageBean.setLocaleCode(language)
                identity.setWorkingParameter("detectedLocale", locale)
        
        return True

    def getPageForStep(self, configurationAttributes, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        if (step == 1):
            return "/detlang"
        else:
            return "/lang"
    
    def getCountAuthenticationSteps(self, configurationAttributes):
        # This module should never "complete", as it does not authenticate the user
        return 3

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1
