# Sign In Canada master authentication script
#
# This script has potentially 5 steps:
#    Step 1: Prompt for language (splash page) (if ui_locales not provided)
#    Step 2: Sign In chooser (if more than one choice)
#            (May include discoverable FIDO2 authentication)
#    Step 3: Registration chooser
#    Step 4: Passport authentication for 1st factor
#    Step 5: Legacy PAI collection (if the RP is transitioning from GCCF)
#    Step 6: Out-of band 2nd factor authentication
#    Step 7: non-discoverable FIDO authentication
#    Step 8: External TOTP via passport (if configured)
#    Step 9: Multi-factor step-up ("Secure your account")
#    Step 10: Out-of band 2nd factor registration
#    Step 11: FIDO2 registration
#    Step 12: Partial Account recovery
#    Step 13: Generic Information / Help / Confirmation page
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

from sic import passport, account, fido, oob

class PersonAuthentication(PersonAuthenticationType):

    STEP_SPLASH = 1
    STEP_CHOOSER = 2
    STEP_REGISTER = 3
    STEP_1FA = 4
    STEP_COLLECT = 5
    STEP_OOB = 6
    STEP_FIDO = 7
    STEP_TOTP = 8
    STEP_UPGRADE = 9
    STEP_OOB_REGISTER = 10
    STEP_FIDO_REGISTER = 11
    STEP_RECOVER = 12
    STEP_RESULT = 13

    # Map of steps to pages
    PAGES = {
            STEP_SPLASH: {"en": "/lang.xhtml", "fr": "/lang.xhtml"},
            STEP_CHOOSER: {"en": "/en/select.xhtml", "fr": "/fr/choisir.xhtml"},
            STEP_REGISTER: {"en": "/en/register.xhtml", "fr": "/fr/registrer.xhtml"},
            STEP_OOB: {"en": "/en/code.xhtml", "fr": "/fr/code.xhtml"},
            STEP_FIDO: {"en": "/en/wa.xhtml", "fr": "/fr/wa.xhtml"},
            STEP_UPGRADE: {"en": "/en/secure.xhtml", "fr": "/fr/securiser.xhtml"},
            STEP_OOB_REGISTER: {"en": "/en/registeroob.xhtml", "fr": "/fr/registrerhb.xhtml"},
            STEP_FIDO_REGISTER: {"en": "/en/registerwa.xhtml", "fr": "/fr/registreraw.xhtml"},
            STEP_RECOVER: {"en": "/en/recover.xhtml", "fr": "/fr/recuperer.xhtml"},
            STEP_RESULT: {"en": "/en/result.xhtml", "fr": "/fr/resultat.xhtml"}
        }

    # MAP of form IDs to steps
    FORMS = {"lang": STEP_SPLASH,
             "chooser": STEP_CHOOSER,
             "register": STEP_REGISTER,
             "oob": STEP_OOB,
             "assertionResponse": STEP_FIDO,
             "secure": STEP_UPGRADE,
             "register_oob":  STEP_OOB_REGISTER,
             "attestationResponse": STEP_FIDO_REGISTER,
             "result" : STEP_RESULT
        }
    
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

        if configurationAttributes.containsKey("fido2_server_uri"):
            # Configure FIDO2
            print ("%s: Enabling FIDO2 support" % self.name)
            self.fido = fido.Fido()
            self.fido.init(configurationAttributes, self.name)

        self.account = account.Account()

        self.oob = oob.OutOfBand()
        self.oob.init(configurationAttributes, self.name)

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
                             "mfaMethod",   # MFA method used to authenticate
                             "mfaId",       # subject identifier for the external TOTP service
                             "oobCode")     # One-time-code for out-of-band

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

        # externalContext.addResponseHeader("Content-Security-Policy", "default-src 'self' https://www.canada.ca; font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://www.canada.ca; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline' https://use.fontawesome.com https://fonts.googleapis.com https://www.canada.ca; script-src 'self' 'unsafe-inline' https://www.canada.ca https://ajax.googleapis.com; connect-src 'self' https://*.fjgc-gccf.gc.ca")

        if step == 1:
            httpRequest = externalContext.getRequest()
            # Bookmark detection
            if httpRequest.getHeader("referer") is None and not rpConfig.get("allowBookmarks"):
                if StringHelper.isNotEmpty(clientUri):
                    facesService.redirectToExternalURL(clientUri)
                    return True
                else:
                    print("%s: prepareForStep. clientUri is missing for client %s" % (self.name, self.getClient(session).getClientName()))
                    return False

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

        if step in {self.STEP_CHOOSER, self.STEP_UPGRADE}:
            # Prepare for chooser page customization.
            for param in ["layout", "chooser", "content"]:
                identity.setWorkingParameter(param, rpConfig[param])

        elif step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_TOTP}: # Passport
            
            passportOptions = {"ui_locales": uiLocales, "exp" : int(time.time()) + 60}

            if step in {self.STEP_1FA, self.STEP_COLLECT}:
                provider = identity.getWorkingParameter("provider")
                if provider is None and len(self.providers) == 1: # Only one provider. Direct Pass-through
                    provider = next(iter(self.providers))
                    identity.setWorkingParameter("provider", provider)
    
            if step == self.STEP_1FA:
                # Coordinate single-sign-on (SSO)
                maxAge = self.getClient(session).getDefaultMaxAge() or 1200
                providerInfo = self.passport.getProvider(provider)
                if (identity.getWorkingParameter("forceAuthn") or (providerInfo["GCCF"] and maxAge < 1200)): # 1200 is 20 minutes, the SSO timeout on GCKey and CBS
                    passportOptions["forceAuthn"] = "true"

            elif step == self.STEP_COLLECT:
                collect = rpConfig.get("collect")
                if collect is not None:
                    passportOptions["allowCreate"] = rpConfig.get("allowCreate") or "false"
                    passportOptions["spNameQualifier"] = collect
                else: # This should never happen
                    print ("%s. prepareForStep: collection entityID is missing" % self.name)
                    return False

            elif step == self.STEP_TOTP:
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

        elif step == self.STEP_OOB and identity.getWorkingParameter("oobCode") is None:
            self.oob.SendOneTimeCode(identity.getWorkingParameter("userId"))

        elif step == self.STEP_FIDO_REGISTER:
            userId = identity.getWorkingParameter("userId")
            attestationRequest = self.fido.generateAttestationRequest(userId)
            identity.setWorkingParameter("attestation_request", attestationRequest)

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

            elif step == self.STEP_TOTP: # 2FA Failed. Redirect back to the RP
                facesService.redirectToExternalURL(self.getClientUri(session))
                return False
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

        elif requestParameters.containsKey("registration"):
            user = self.account.register(requestParameters)
            if user:
                identity.setWorkingParameter("userId", user.getUserId())
            else:
                return False

        elif requestParameters.containsKey("attestationResponse"):
            attestationResponse = ServerUtil.getFirstValue(requestParameters, "attestationResponse")
            if attestationResponse:
                return self.fido.registerFido2(attestationResponse)
            else:
                self.account.delete(identity.getWorkingParameter("userId"))
                return False

        elif requestParameters.containsKey("assertionResponse"):
            assertionResponse = ServerUtil.getFirstValue(requestParameters, "assertionResponse")
            if assertionResponse:
                return self.fido.authenticateFido2(assertionResponse)
            else:
                return False

        elif requestParameters.containsKey("oob"):
            return self.oob.AuthenticateOutOfBand(requestParameters)

        elif requestParameters.containsKey("register_oob"):
            return self.oob.RegisterOutOfBand(requestParameters)
 
        elif requestParameters.containsKey("secure"):
            identity.setWorkingParameter("mfaMethod", self.getFormButton(requestParameters))

        elif requestParameters.containsKey("navigate"):
            print ("%s: Navigate to: %s." % (self.name, self.getFormButton(requestParameters)))

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
            step = self.STEP_TOTP

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

        elif step == self.STEP_TOTP:
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

            if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

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

        if uiLocales is not None:
            language = uiLocales[:2].lower()

        if step == 1 and uiLocales is not None:
            if len(self.providers) > 1:
                step = self.STEP_CHOOSER
            else: # Direct pass-through
                step = self.STEP_1FA

        if step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_TOTP}: # Passport
            # identity.getWorkingParameters().remove("abort")
            return "/auth/passport/passportlogin.xhtml"

        page = self.PAGES.get(step)
        if page is not None:
            return page[language]
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

        # Handle language toggles
        if requestParameters.containsKey("lang"):
            step = self.FORMS.get(ServerUtil.getFirstValue(requestParameters, "lang:step"))

        # Determine the step from the form name (handles back button etc.)
        form = self.getFormName(requestParameters)
        if form in self.FORMS:
            step = self.FORMS.get(form)

        print ("Step %s, Form %s" % (step, form))

        if step == 1:
             # Determine if SPLASH, CHOOSER, or 1FA
            if requestParameters.containsKey("lang"):
                step = self.STEP_SPLASH
            elif requestParameters.containsKey("chooser") or requestParameters.containsKey("assertionResponse"):
                step = self.STEP_CHOOSER
            elif requestParameters.containsKey("user") or requestParameters.containsKey("failure"):
                step = self.STEP_1FA

        if requestParameters.containsKey("navigate"):
            target = self.getFormButton(requestParameters)
            if target == "register":
                return self.gotoStep(self.STEP_REGISTER)
            elif target == "cancel":
                return self.gotoStep(self.STEP_CHOOSER)
            elif target != "continue":
                print ("%s: Invalid navigation target: %s"  % (self.name, target))

        if step == self.STEP_SPLASH:
            if len(self.providers) == 1:
                return self.gotoStep(self.STEP_1FA)
            else:
                return self.gotoStep(self.STEP_CHOOSER)

        if step == self.STEP_CHOOSER:
            if requestParameters.containsKey("assertionResponse") and not ServerUtil.getFirstValue(requestParameters, "assertionResponse"):
                return self.gotoStep(self.STEP_CHOOSER) # Cancel or Fail
            elif not requestParameters.containsKey("assertionResponse"):
                return self.gotoStep(self.STEP_1FA)

        if step == self.STEP_1FA:
            if requestParameters.containsKey("failure"): # User cancelled
                return self.gotoStep(self.STEP_CHOOSER)
            elif requestParameters.containsKey("chooser"): # User double-clicked
                return self.gotoStep(self.STEP_1FA)
            else:
                if providerInfo["GCCF"] and "collect" in rpConfig:
                    user = userService.getUser(identity.getWorkingParameter("userId"), "persistentId")
                    if self.account.getSamlSubject(user, rpConfig["collect"]) is None: # SAML PAI collection
                        return self.gotoStep(self.STEP_COLLECT)

        if step in {self.STEP_1FA, self.STEP_COLLECT}:
            mfaMethods = rpConfig.get("mfa")
            if mfaMethods is not None:
                user = userService.getUser(identity.getWorkingParameter("userId"), "externalId", "mobile", "mail")
                if "fido" in mfaMethods and userService.countFido2RegisteredDevices(user.getUserId()) > 0:
                    identity.setWorkingParameter("mfaMethod", "fido")
                    return self.gotoStep(self.STEP_FIDO)
                elif "totp" in mfaMethods and self.account.getExternalUid(user, "mfa") is not None:
                    identity.setWorkingParameter("mfaMethod", "totp")
                    return self.gotoStep(self.STEP_TOTP)
                elif "sms" in mfaMethods and user.getAttribute("mobile") is not None:
                    identity.setWorkingParameter("mfaMethod", "sms")
                    return self.gotoStep(self.STEP_OOB)
                elif "email" in mfaMethods and user.getAttribute("mail") is not None:
                    identity.setWorkingParameter("mfaMethod", "email")
                    return self.gotoStep(self.STEP_OOB)
                else: # No acceptable method is registered
                    return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_OOB_REGISTER:
            if identity.getWorkingParameter("oobCode"):
                return self.gotoStep(self.STEP_OOB)

        if step == self.STEP_UPGRADE:
            target = self.getFormButton(requestParameters)
            if target == "fido":
                return self.gotoStep(self.STEP_REGISTER)
            elif target == "totp":
                return self.gotoStep(self.STEP_TOTP)
            elif target in {"email", "sms"}:
                return self.gotoStep(self.STEP_OOB_REGISTER)

        if step == self.STEP_REGISTER:
            if requestParameters.containsKey("registration:register"):
                if identity.getWorkingParameter("userId"):
                    return self.gotoStep(self.STEP_FIDO_REGISTER)
                else:
                    return self.gotoStep(self.STEP_REGISTER)
            else: # Cancel
                return self.gotoStep(self.STEP_CHOOSER)

        if step == self.STEP_FIDO_REGISTER:
            if requestParameters.containsKey("attestationResponse"):
                if ServerUtil.getFirstValue(requestParameters, "attestationResponse"):
                    return self.gotoStep(self.STEP_RESULT)
                else: # Failed
                    return self.gotoStep(self.STEP_CHOOSER)
            else: # Cancel
                return self.gotoStep(self.STEP_CHOOSER)

        # if we get this far we're done
        identity.setWorkingParameter("stepCount", originalStep)
        return -1

    ### Form response parsing

    def getFormName(self, requestParameters):
        for parameter in requestParameters.keySet():
            if parameter.find(":") == -1:
                return parameter
        return None

    def getFormButton(self, requestParameters):
        for parameter in requestParameters.keySet():
            start = parameter.find(":")
            if start > -1:
                return parameter[start + 1:]
        return None

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
        #clientKey = "oidc:%s" % client.getClientId()
        #if clientKey in self.rpConfigCache:
        #    return self.rpConfigCache[clientKey]

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
        #self.rpConfigCache[clientKey] = rpConfig
        return rpConfig
