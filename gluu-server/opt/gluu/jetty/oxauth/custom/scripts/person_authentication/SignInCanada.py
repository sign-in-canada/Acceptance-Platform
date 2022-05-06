# Sign In Canada master authentication script
#
# This script has potentially 5 steps:
#    Step 1: Prompt for language (splash page) (if ui_locales not provided)
#    Step 2: Choose 1st factor authentication provider (if more than one choice)
#    Step 3: Passport authentication for 1st factor
#    Step 4: Legacy PAI collection (if the RP is transitioning from GCCF)
#    Step 5: External MFA via passport (if configured)
#    Step 6: FIDO2 authentication
#    Step 7: FIDO2 registration
#    Step 8: FIDO2 registration confirmation
#
# The actual steps performed will depend on thw workflow. Note that if steps 1 or 2 are skipped
# then the step # passed by Gluu will always be 1 for the first step performed, regardless
# of the numbers above.
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
from org.gluu.fido2.client import Fido2ClientFactory
from org.gluu.util import StringHelper

from java.util import Arrays
from java.util.concurrent.locks import ReentrantLock
from javax.ws.rs.core import Response
from javax.ws.rs import ClientErrorException

from com.microsoft.applicationinsights import TelemetryClient

import java
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

    STEP_SPLASH = 1
    STEP_CHOOSER = 2
    STEP_1FA = 3
    STEP_COLLECT = 4
    STEP_2FA = 5
    STEP_FIDO_AUTH = 6
    STEP_FIDO_REGISTER = 7
    STEP_FIDO_CONFIRM = 8
    
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
        
        # Configure FIDO2
        if configurationAttributes.containsKey("fido2_server_uri"):
            print ("%s: Enabling FIDO2 support" % self.name)
            self.fido2_server_uri = configurationAttributes.get("fido2_server_uri").getValue2()
            self.fido2_domain = None
            if configurationAttributes.containsKey("fido2_domain"):
                self.fido2_domain = configurationAttributes.get("fido2_domain").getValue2()
            self.metaDataLoaderLock = ReentrantLock()
            self.fidoMetaDataConfiguration = None

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
        return Arrays.asList("stepCount",   # Used to complete the workflow
                             "provider",    # The 1FA provider chosen by the user
                             "abort",       # Used to trigger error abort back to the RP
                             "forceAuthn",  # Used to force authentication when prompt=login
                             "userId",      # Used to keep track of the user across multiple requests
                             "mfaId",       # Used to bind a 2nd factor credential into the session
                             "mfaFallback") # Used to bypass Fido authnetication

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesService = CdiUtil.bean(FacesService)
        userService = CdiUtil.bean(UserService)
        
        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        externalContext = facesResources.getFacesContext().getExternalContext()
        uiLocales = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)

        rpConfig = self.getRPConfig(session)
        clientUri = self.getClientUri(session)

        externalContext.addResponseHeader("Content-Security-Policy", "default-src 'self' https://www.canada.ca; font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://www.canada.ca; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline' https://use.fontawesome.com https://fonts.googleapis.com https://www.canada.ca; script-src 'self' 'unsafe-inline' https://www.canada.ca https://ajax.googleapis.com; connect-src 'self' https://*.fjgc-gccf.gc.ca")

        if step == 1:
            httpRequest = externalContext.getRequest()
            # Bookmark detection
            #if httpRequest.getHeader("referer") is None:
            #    if StringHelper.isNotEmpty(clientUri):
            #        facesService.redirectToExternalURL(clientUri)
            #        return True
            #    else:
            #        print("%s: prepareForStep. clientUri is missing for client %s" % (self.name, self.getClient(session).getClientName()))
            #        return False

            # forceAuthn workaround
            prompt2 = httpRequest.getParameter("prompt2")
            if prompt2 == "login":
                identity.setWorkingParameter("forceAuthn", True)

            # step could actually be 2, or 3
            if uiLocales is not None:
                if len(self.providers) > 1:
                    step = self.STEP_CHOOSER
                else:
                    step = self.STEP_1FA


        if identity.getWorkingParameter("abort"): # Back button workaround
            # Obtain the client URI of the current client from the client configuration
            if len(self.providers) == 1: # Pass through, so send them back to the client
                if StringHelper.isNotEmpty(clientUri):
                    facesService.redirectToExternalURL(clientUri)
                    return True
                else:
                    print("%s: prepareForStep. clientUri is missing for client %s" % (self.name, self.getClient(session).getClientName()))
                    return False
            else: # reset the chooser
                identity.setWorkingParameter("provider", None)

        if step == self.STEP_CHOOSER:
            # Prepare for chooser page customization.
            for param in ["layout", "chooser", "content"]:
                identity.setWorkingParameter(param, rpConfig[param])

        elif step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_2FA}: # Passport
            
            passportOptions = {"ui_locales": uiLocales, "exp" : int(time.time()) + 60}

            if step in {self.STEP_1FA, self.STEP_COLLECT}:
                provider = identity.getWorkingParameter("provider")
                if provider is None and len(self.providers) == 1: # Only one provider. Direct Pass-through
                    provider = next(iter(self.providers))
                    identity.setWorkingParameter("provider", provider)
    
            if step == self.STEP_1FA:
                # Coordinate single-sign-on (SSO)
                maxAge = (sessionAttributes.get(AuthorizeRequestParam.MAX_AGE) or self.getClient(session).getDefaultMaxAge())
                if (identity.getWorkingParameter("forceAuthn")
                    or ("GCCF" in self.passport.getProvider(provider)["options"] and maxAge < 1200)): # 1200 is 20 minutes, the SSO timeout on GCKey and CBS
                    passportOptions["forceAuthn"] = "true"

            elif step == self.STEP_COLLECT:
                collect = rpConfig.get("collect")
                if collect is not None:
                    passportOptions["allowCreate"] = "false"
                    passportOptions["spNameQualifier"] = collect
                else: # This should never happen
                    print ("%s. prepareForStep: collection entityID is missing" % self.name)
                    return False

            elif step == self.STEP_2FA:
                provider = rpConfig.get("mfaProvider")
                if provider is None:
                    print("%s: prepareForStep. mfaProvider is missing!" % self.name)
                    return False
                mfaId = identity.getWorkingParameter("mfaId")
                if mfaId is None:
                    print("%s: prepareForStep. mfaId is missing!" % self.name)
                    return False
                else:
                    passportOptions["login_hint"] = mfaId
                    # The following parameters are redundant, but currently required by the 2ndFaaS
                    passportOptions["redirect_uri"] = self.passport.getProvider(provider)["callbackUrl"]
                    passportOptions["response_type"] = "code"
                    passportOptions["scope"] = "openid profile"

            # Set the abort flag to handle back button
            identity.setWorkingParameter("abort", True)
            # Send the request to passport
            passportRequest = self.passport.createRequest(provider, passportOptions)
            facesService.redirectToExternalURL(passportRequest)

        elif step in {self.STEP_FIDO_REGISTER, self.STEP_FIDO_AUTH}:
            userId = identity.getWorkingParameter("userId")
            metaDataConfiguration = self.getFidoMetaDataConfiguration()

            if step == self.STEP_FIDO_REGISTER:
                try:
                    attestationService = Fido2ClientFactory.instance().createAttestationService(metaDataConfiguration)
                    attestationRequest = json.dumps({'username': userId,
                                                     'displayName': userId,
                                                     'attestation' : 'direct',
                                                     'timeout': 120000,
                                                     'userVerification': 'discouraged'}, separators=(',', ':'))
                    attestationResponse = attestationService.register(attestationRequest).readEntity(java.lang.String)
                except ClientErrorException as ex:
                    print ("%s. Prepare for step. Failed to start FIDO2 attestation flow. Exception:" % self.name, sys.exc_info()[1])
                    return False
                identity.setWorkingParameter("fido2_attestation_request", ServerUtil.asJson(attestationResponse))
                print(ServerUtil.asJson(attestationResponse))

            elif step == self.STEP_FIDO_AUTH:
                userId = identity.getWorkingParameter("userId")
                metaDataConfiguration = self.getFidoMetaDataConfiguration()
                fidoDeviceCount = userService.countFidoAndFido2Devices(userId, self.fido2_domain)
                try:
                    assertionService = Fido2ClientFactory.instance().createAssertionService(metaDataConfiguration)
                    assertionRequest = json.dumps({'username': userId, 'timeout': 120000, 'userVerification': 'discouraged'}, separators=(',', ':'))
                    assertionResponse = assertionService.authenticate(assertionRequest).readEntity(java.lang.String)
                except ClientErrorException as ex:
                    print ("%s. Prepare for step. Failed to start FIDO2 assertion flow. Exception:" %self.name, sys.exc_info()[1])
                    return False
                identity.setWorkingParameter("fido2_assertion_request", ServerUtil.asJson(assertionResponse))

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

        # Clear the abort flag
        identity.setWorkingParameter("abort", False)

        if requestParameters.containsKey("user"):
            # Successful response from passport
            return self.authenticatePassportUser(configurationAttributes, requestParameters, step)

        elif requestParameters.containsKey("failure"):
            # This means that passport returned an error
            if step <= self.STEP_1FA: # User Cancelled during login
                if len(self.providers) == 1: # One provider. Redirect back to the RP
                    facesService.redirectToExternalURL(self.getClientUri(session))
                else: # Clear the previous choice to re-display the chooser
                    # locale = ServerUtil.getFirstValue(requestParameters, "ui_locale") # TODO: Update passport to send language onerror
                    # sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
                    identity.setWorkingParameter("provider", None)
            elif (step == self.STEP_COLLECT
                  and ServerUtil.getFirstValue(requestParameters, "failure") == "InvalidNameIDPolicy"): # PAI Collection failed. If it's a SAML SP, Create a new SIC PAI
                spNameQualifier = sessionAttributes.get("entityId")
                if spNameQualifier is not None:
                    user = userService.getUser(identity.getWorkingParameter("userId"), "uid", "persistentId")
                    user = self.account.addSamlSubject(user, spNameQualifier)
                    userService.updateUser(user)
                if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                    return authenticationService.authenticate(identity.getWorkingParameter("userId"))

            elif step == self.STEP_2FA: # 2FA Failed. Redirect back to the RP
                facesService.redirectToExternalURL(self.getClientUri(session))
            else:
                print ("%s: Invalid passport failure in step %s." % (self.name, step))
                return False

        elif requestParameters.containsKey("lang"):
            # Manually selected language
            locale = self.getFormButton(requestParameters)
            if locale in {"en-CA", "fr-CA"}:
                languageBean.setLocaleCode(locale)
                sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)
            else:
                return False

        elif requestParameters.containsKey("chooser"):
            # Chooser page
            choice = self.getFormButton(requestParameters)
            if choice == "gckeyregister": choice = "gckey" #Hack!
            if choice in self.providers:
                identity.setWorkingParameter("provider", choice)
            else:
                print ("%s: Invalid provider choice: %s." % (self.name, choice))
                return False

        elif requestParameters.containsKey("fido2Registration"):
            return self.registerFido2(identity.getWorkingParameter("userId"), requestParameters)

        elif requestParameters.containsKey("fido2Authentication"):
            return self.authenticateFido2(identity.getWorkingParameter("userId"), requestParameters)

        elif requestParameters.containsKey("fido2Nav"):
            option = self.getFormButton(requestParameters)
            if option == "use2FA":
                identity.setWorkingParameter("mfaFallback", True)
            elif option == "recover":
                user = userService.getUser(identity.getWorkingParameter("userId"), "inum", "uid")
                self.account.removeFido2Registrations(user)
            elif option in {"decline", "continue"}:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        else: # Invalid response
            print ("%s: Invalid form submission: %s." % (self.name, requestParameters.keySet().toString()))
            return False

        return True

    def authenticatePassportUser(self, configurationAttributes, requestParameters, step):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)

        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()
        rpConfig = self.getRPConfig(session)

        externalProfile = self.passport.handleResponse(requestParameters)
        if externalProfile is None:
            return False
        provider = externalProfile["provider"]

        # Can't trust the step parameter
        if identity.getWorkingParameter("userId") is None:
            step = self.STEP_1FA
        elif provider == identity.getWorkingParameter("provider"):
            step = self.STEP_COLLECT
        elif provider == rpConfig.get("mfaProvider"):
            step = self.STEP_2FA

        if step == self.STEP_1FA:
            if provider not in self.providers:
                # Unauthorized provider!
                return False

            provider = externalProfile["provider"]
            if step == self.STEP_1FA and provider not in self.providers:
                # Unauthorized provider!
                return False
            else:
                providerInfo = self.passport.getProvider(provider)

            if providerInfo["GCCF"]:
                sessionAttributes.put("authnInstant", externalProfile["authnInstant"][0])
                sessionAttributes.put("persistentId", externalProfile["persistentId"][0])
                sessionAttributes.put("sessionIndex", externalProfile["sessionIndex"][0])

            # Find or create the user account
            user = self.account.find(externalProfile)
            if user is None:
                user = self.account.create(externalProfile)
                newUser = True
            else:
                newUser = False
                userChanged = False
            identity.setWorkingParameter("userId", user.getUserId())

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
            spNameQualifier = sessionAttributes.get("entityId")
            if spNameQualifier is not None and "collect" not in rpConfig and self.account.getSamlSubject(user, spNameQualifier) is None:
                user = self.account.addSamlSubject(user, spNameQualifier)
                userChanged = True

            # IF MFA is enabled, grab the mfaId, or create if needed
            if rpConfig.get("mfaProvider"): 
                mfaId = self.account.getExternalUid(user, "mfa")
                if mfaId is None:
                    mfaId = self.account.addExternalUid(user, "mfa")
                    userChanged = True
                identity.setWorkingParameter("mfaId", mfaId)

            if newUser:
                userService.addUser(user, True)
            elif userChanged:
                userService.updateUser(user)

            if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        elif step == self.STEP_COLLECT:
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
                provider = identity.getWorkingParameter("provider")
                self.account.addOpenIdSubject(user, client, provider + nameId)

            if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        elif step == self.STEP_2FA:
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

            userId = identity.getWorkingParameter("userId")
            if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        return True

    def registerFido2(self, userId, requestParameters):

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        session = identity.getSessionId()

        tokenResponse = ServerUtil.getFirstValue(requestParameters, "fido2Registration")
        print ("%s. Authenticate. Got fido2 registration response: %s" % (self.name, tokenResponse))
        metaDataConfiguration = self.getFidoMetaDataConfiguration()
        attestationService = Fido2ClientFactory.instance().createAttestationService(metaDataConfiguration)
        attestationStatus = attestationService.verify(tokenResponse)

        if attestationStatus.getStatus() != Response.Status.OK.getStatusCode():
            print ("%s. Authenticate. Got invalid registration status from Fido2 server" % self.name)
            return False

        return authenticationService.authenticate(identity.getWorkingParameter("userId"))

    def authenticateFido2(self, userId, requestParameters):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        session = identity.getSessionId()

        tokenResponse = ServerUtil.getFirstValue(requestParameters, "fido2Authentication")
        print ("%s. Authenticate. Got fido2 authentication response: %s" % (self.name, tokenResponse))
        metaDataConfiguration = self.getFidoMetaDataConfiguration()
        assertionService = Fido2ClientFactory.instance().createAssertionService(metaDataConfiguration)
        assertionStatus = assertionService.verify(tokenResponse)
        authenticationStatusEntity = assertionStatus.readEntity(java.lang.String)

        if assertionStatus.getStatus() != Response.Status.OK.getStatusCode():
            print ("%s. Authenticate. Got invalid authentication status from Fido2 server" % self.name)
            return False

        return authenticationService.authenticate(identity.getWorkingParameter("userId"))

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

        if uiLocales is not None:
            language = uiLocales[:2].lower()

        if step == 1 and uiLocales is not None:
            if len(self.providers) > 1:
                step = self.STEP_CHOOSER
            else: # Direct pass-through
                step = self.STEP_1FA

        if step == self.STEP_SPLASH:
            return "/lang.xhtml"

        elif step == self.STEP_CHOOSER: # Chooser page
            if language == "fr":
                return "/fr/choisir.xhtml"
            else:
                return "/en/select.xhtml"

        elif step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_2FA}: # Passport
            # identity.getWorkingParameters().remove("abort")
            return "/auth/passport/passportlogin.xhtml"

        elif step == self.STEP_FIDO_AUTH: # FIDO Authentication
            if language == "fr":
                return "/fr/wa.xhtml"
            else:
                return "/en/wa.xhtml"

        elif step == self.STEP_FIDO_REGISTER: # FIDO Reggistration
            if language == "fr":
                return "/fr/waregistrer.xhtml"
            else:
                return "/en/waregister.xhtml"

        elif step == self.STEP_FIDO_CONFIRM: # FIDO Registration
            if language == "fr":
                return "/fr/wasucces.xhtml"
            else:
                return "/en/wasuccess.xhtml"

        else:
            print("%s. getPageForStep. Unexpected step # %s" % (self.name, step))
            return "/error.xhtml"

    def getCountAuthenticationSteps(self, configurationAttributes):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
            
        identity = CdiUtil.bean(Identity)
        stepCount = identity.getWorkingParameter("stepCount")
        
        if stepCount is None:
            return 255 # not done yet
        else:
            return stepCount
 
    def gotoStep(self, step):
        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()

        # Mark all previous steps as passed so the workflow can skip steps
        for i in range(1, step + 1):
            sessionAttributes.put("auth_step_passed_%s" % i, "true")
        return step

    def getNextStep(self, configurationAttributes, requestParameters, step):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
            
        # Inject dependencies
        userService = CdiUtil.bean(UserService)
        identity = CdiUtil.bean(Identity)
        session = identity.getSessionId()
        rpConfig = self.getRPConfig(session)
        provider = identity.getWorkingParameter("provider")
        if provider is not None:
            providerInfo = self.passport.getProvider(provider)

        originalStep = step
        if step == 1:
             # Determine if SPLASH, CHOOSER, or 1FA
            if requestParameters.containsKey("lang"):
                step = self.STEP_SPLASH
            elif requestParameters.containsKey("chooser"):
                step = self.STEP_CHOOSER
            elif requestParameters.containsKey("user") or requestParameters.containsKey("failure"):
                step = self.STEP_1FA
                
        if step == self.STEP_SPLASH:
            if len(self.providers) == 1:
                return self.gotoStep(self.STEP_1FA)
            else:
                return self.gotoStep(self.STEP_CHOOSER)

        if step == self.STEP_CHOOSER:
            if requestParameters.containsKey("lang"):
                return self.gotoStep(self.STEP_CHOOSER) # Language toggle
            else:
                return self.gotoStep(self.STEP_1FA)

        userId = identity.getWorkingParameter("userId")
        if step == self.STEP_1FA:
            if requestParameters.containsKey("failure"): # User cancelled
                return self.gotoStep(self.STEP_CHOOSER)
            else:
                if providerInfo["GCCF"] and "collect" in rpConfig:
                    user = userService.getUser(userId, "persistentId")
                    if self.account.getSamlSubject(user, rpConfig["collect"]) is None: # SAML PAI collection
                        return self.gotoStep(self.STEP_COLLECT)

        if step in {self.STEP_1FA, self.STEP_COLLECT}:
            if rpConfig.get("fido") and userService.countFidoAndFido2Devices(userId, self.fido2_domain) > 0:
                return self.gotoStep(self.STEP_FIDO_AUTH)
            if rpConfig.get("mfaProvider"): # 2FA
                return self.gotoStep(self.STEP_2FA)

        if step == self.STEP_2FA:
            if rpConfig.get("fido") and userService.countFidoAndFido2Devices(userId, self.fido2_domain) == 0:
                return self.gotoStep(self.STEP_FIDO_REGISTER)
        
        if step == self.STEP_FIDO_AUTH:
            if requestParameters.containsKey("lang"):
                return self.gotoStep(self.STEP_FIDO_AUTH) # Language toggle
            elif not requestParameters.containsKey("fido2Authentication"):
                return self.gotoStep(self.STEP_2FA) # If the don't have thier authentiator then fallback to 2FA

        if step == self.STEP_FIDO_REGISTER:
            if requestParameters.containsKey("lang"):
                return self.gotoStep(self.STEP_FIDO_REGISTER) # Language toggle
            elif requestParameters.containsKey("fido2Registration"):
                return self.gotoStep(self.STEP_FIDO_CONFIRM)

        if step == self.STEP_FIDO_CONFIRM:
            if requestParameters.containsKey("lang"):
                return self.gotoStep(self.STEP_FIDO_CONFIRM) # Language toggle

        # if we get this far we're done
        identity.setWorkingParameter("stepCount", originalStep)
        return -1

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
            print ("%s. Initialization. Downloading Fido2 metadata" % self.name)
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
