# Sign In Canada master authentication script
#
# This script has potentially 15 steps:
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
#    Step 11: TOTP registration
#    Step 12: FIDO2 registration
#    Step 13: Partial Account recovery
#    Step 14: Generic Information / Help / Confirmation page
#    Step 15: Abort authentication and redirtect back to the RP
#
# The actual steps performed will depend on thw workflow. Note that if steps 1 or 2 are skipped
# then the step # passed by Gluu will always be 1 for the first step performed, regardless
# of the numbers above.
#
# Author: Doug Harris

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import AuthenticationService, UserService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources, FacesService
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam
from org.gluu.util import StringHelper

from java.util import Arrays, Date
from java.time import Instant
from javax.faces.application import FacesMessage

from com.microsoft.applicationinsights import TelemetryClient

import java
import sys
import json
import time
import uuid

class SICError(Exception):
    """Base class for exceptions in this module."""
    pass

sys.path.append("/opt/gluu/jetty/oxauth/custom/scripts")

REMOTE_DEBUG = False

if REMOTE_DEBUG:
    try:
        sys.path.append("/opt/libs/pydevd")
        import pydevd
    except ImportError as ex:
        print ("Failed to import pydevd: %s" % ex)
        raise

from sic import passport, account, fido, oob, rputils

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
    STEP_TOTP_REGISTER = 11
    STEP_FIDO_REGISTER = 12
    STEP_RECOVER = 13
    STEP_RESULT = 14
    STEP_ABORT = 15

    # Map of steps to pages
    PAGES = {
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
    FORMS = {"chooser": STEP_CHOOSER,
             "register": STEP_REGISTER,
             "oob": STEP_OOB,
             "assertionResponse": STEP_FIDO,
             "secure": STEP_UPGRADE,
             "register_oob":  STEP_OOB_REGISTER,
             "register_wa":  STEP_FIDO_REGISTER,
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
        providersParam = configurationAttributes.get("providers")
        if providersParam is None:
            print ("%s: Providers parameter is missing from config!"  % self.name)
            return False
        else:
            self.providers = set([item.strip() for item in providersParam.getValue2().split(",")])

        mfaMethodsParam = configurationAttributes.get("mfa_methods")
        if mfaMethodsParam is not None:
            self.mfaMethods = list([item.strip() for item in mfaMethodsParam.getValue2().split(",")])
        else:
            self.mfaMethods = []

        if configurationAttributes.containsKey("totp_timeout"):
            self.totpTimeout = StringHelper.toInteger(configurationAttributes.get("totp_timeout").getValue2())
            print ("%s. TOTP timeout is %s seconds." % (self.name, self.totpTimeout))
        else:
            self.totpTimeout = None

        self.rputils = rputils.RPUtils()
        self.rputils.init(configurationAttributes, self.name)

        self.passport = passport.Passport()
        self.passport.init(configurationAttributes, self.name)

        if configurationAttributes.containsKey("fido2_server_uri"):
            # Configure FIDO2
            print ("%s: Enabling FIDO2 support" % self.name)
            self.fido = fido.Fido()
            self.fido.init(configurationAttributes, self.name)

        self.account = account.Account()

        if self.mfaMethods:
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

        client = self.rputils.getClient(identity.getSessionId())
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
                             "oobChannel",  # Chosen channel for OOB (sms or email)
                             "oobCode",     # One-time-code for out-of-band
                             "oobContact",  # Mobile number or email address being registered for OOB
                             "oobExpiry",   # Timestamp when OOB expires
                             "content")     # RP Content identifier

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
        uiLocales = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)

        rpConfig = self.rputils.getRPConfig(session)
        clientUri = self.rputils.getClientUri(session)

        # externalContext.addResponseHeader("Content-Security-Policy", "default-src 'self' https://www.canada.ca; font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://www.canada.ca; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline' https://use.fontawesome.com https://fonts.googleapis.com https://www.canada.ca; script-src 'self' 'unsafe-inline' https://www.canada.ca https://ajax.googleapis.com; connect-src 'self' https://*.fjgc-gccf.gc.ca")

        print ("Preparing for step %s" % step)
        print ("View ID: %s" % facesResources.getFacesContext().getViewRoot().getViewId())

        if step == 1:
            externalContext = facesResources.getExternalContext()
            # Bookmark detection
            cookies = externalContext.getRequestCookieMap()
            if not cookies.containsKey("bmd") and not rpConfig.get("allowBookmarks"):
                if StringHelper.isNotEmpty(clientUri):
                    facesService.redirectToExternalURL(clientUri)
                    return True
                else:
                    print("%s: prepareForStep. clientUri is missing for client %s" % (self.name, self.rputils.getClient(session).getClientName()))
                    return False

            # forceAuthn workaround
            httpRequest = externalContext.getRequest()
            prompt2 = httpRequest.getParameter("prompt2")
            if prompt2 == "login":
                identity.setWorkingParameter("forceAuthn", True)

            # step could actually be 2, or 3
            if uiLocales is not None:
                if len(self.providers) > 1:
                    step = self.STEP_CHOOSER
                    self.telemetryClient.trackEvent("1FA Choice Offered", {"sid" : session.getOutsideSid()}, None)
                else:
                    step = self.STEP_1FA

        if identity.getWorkingParameter("abort"): # Back button workaround
            if step == self.STEP_TOTP_REGISTER:
                if len(self.mfaMethods) > 1:
                    step = self.STEP_UPGRADE
                    self.telemetryClient.trackEvent("2FA Choice Offered", {"sid" : session.getOutsideSid()}, None)
                elif len(self.providers) == 1: # Pass through, so send them back to the client
                    step = self.STEP_ABORT
                else:
                    step = self.STEP_CHOOSER
                    self.telemetryClient.trackEvent("1FA Choice Offered", {"sid" : session.getOutsideSid()}, None)
            elif step == self.STEP_1FA:
                if len(self.providers) == 1: # Pass through, so send them back to the client
                    step = self.STEP_ABORT
                else:
                    # reset the chooser
                    identity.setWorkingParameter("provider", None)
                    step = self.STEP_CHOOSER

        if step == self.STEP_ABORT:
            if StringHelper.isNotEmpty(clientUri):
                facesService.redirectToExternalURL(clientUri)
                return True
            else:
                print("%s: prepareForStep. clientUri is missing for client %s" % (self.name, self.rputils.getClient(session).getClientName()))
                return False

        # Prepare for page customization.
        for param in ["layout", "chooser", "content"]:
            identity.setWorkingParameter(param, rpConfig.get(param))

        if identity.getWorkingParameter("userId") is not None and len(self.mfaMethods) > 0:
            mfaRegistered = identity.getWorkingParameter("mfaMethod")
            for mfaType in self.mfaMethods:
                identity.setWorkingParameter(mfaType + "-accepted", mfaType in self.mfaMethods)
                if mfaRegistered == mfaType: # Don't allow downgrading methods
                    break

        if step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_TOTP_REGISTER, self.STEP_TOTP}: # Passport
            passportOptions = {"ui_locales": uiLocales, "exp" : int(time.time()) + 60}

            if step in {self.STEP_1FA, self.STEP_COLLECT}:
                provider = identity.getWorkingParameter("provider")
                telemetry = {"sid" : session.getOutsideSid(), "provider": provider}
                if provider == "gckeyregister": # Hack
                    provider = "gckey"
                if provider is None and len(self.providers) == 1: # Only one provider. Direct Pass-through
                    provider = next(iter(self.providers))
                    identity.setWorkingParameter("provider", provider)
    
            if step == self.STEP_1FA:
                # Coordinate single-sign-on (SSO)
                maxAge = self.rputils.getClient(session).getDefaultMaxAge() or 1200
                providerInfo = self.passport.getProvider(provider)
                if (identity.getWorkingParameter("forceAuthn") or (providerInfo["GCCF"] and maxAge < 1200)): # 1200 is 20 minutes, the SSO timeout on GCKey and CBS
                    passportOptions["forceAuthn"] = "true"
                self.telemetryClient.trackEvent("1FA Request", telemetry, None)

            elif step == self.STEP_COLLECT:
                collect = rpConfig.get("collect")
                if collect is not None:
                    passportOptions["allowCreate"] = rpConfig.get("allowCreate") or "false"
                    passportOptions["spNameQualifier"] = collect
                else: # This should never happen
                    print ("%s. prepareForStep: collection entityID is missing" % self.name)
                    return False
                telemetry["spNameQualifier"] = collect
                self.telemetryClient.trackEvent("Collection Request", telemetry, None)

            elif step in {self.STEP_TOTP, self.STEP_TOTP_REGISTER}:
                provider = rpConfig.get("mfaProvider")
                if provider is None:
                    print("%s: prepareForStep. mfaProvider is missing!" % self.name)
                    return False

                telemetry = {"sid" : session.getOutsideSid(), "provider": provider}

                if step == self.STEP_TOTP_REGISTER:
                    mfaId = uuid.uuid4().hex
                else:
                    user = userService.getUser(identity.getWorkingParameter("userId"), "uid", "oxExternalUid")
                    mfaId = self.account.getExternalUid(user, "mfa")
                identity.setWorkingParameter("mfaId", mfaId)

                passportOptions["login_hint"] = mfaId
                # The following parameters are redundant, but currently required by the 2ndFaaS
                passportOptions["redirect_uri"] = self.passport.getProvider(provider)["callbackUrl"]
                passportOptions["response_type"] = "code"
                passportOptions["scope"] = "openid profile"

                event = "TOTP %s Request" % ("Registration" if step == self.STEP_TOTP_REGISTER else "Authentication")
                self.telemetryClient.trackEvent(event, telemetry, None)

            # Set the abort flag to handle back button
            identity.setWorkingParameter("abort", True)
            # Send the request to passport
            passportRequest = self.passport.createRequest(provider, passportOptions)
            facesService.redirectToExternalURL(passportRequest)

        elif step == self.STEP_UPGRADE:
            self.telemetryClient.trackEvent("2FA Choice Offered", {"sid" : session.getOutsideSid()}, None)

        elif step == self.STEP_OOB:
            if identity.getWorkingParameter("oobChannel") is None:
                identity.setWorkingParameter("oobChannel", identity.getWorkingParameter("mfaMethod"))
            if identity.getWorkingParameter("oobCode") is None:
                self.oob.SendOneTimeCode(identity.getWorkingParameter("userId"),
                                         identity.getWorkingParameter("oobChannel"),
                                         identity.getWorkingParameter("oobContact"))

        elif step == self.STEP_FIDO:
            userId = identity.getWorkingParameter("userId")
            assertionRequest = self.fido.generateAssertionRequest(userId)
            identity.setWorkingParameter("assertion_request", assertionRequest)

        elif step == self.STEP_FIDO_REGISTER:
            userId = identity.getWorkingParameter("userId")
            attestationRequest = self.fido.generateAttestationRequest(userId)
            identity.setWorkingParameter("attestation_request", attestationRequest)

        return True
        
    def authenticate(self, configurationAttributes, requestParameters, step):
        
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)

        session = identity.getSessionId()
        sessionAttributes = session.getSessionAttributes()

        # Clear the abort flag
        identity.setWorkingParameter("abort", False)

        telemetry = {"sid" : session.getOutsideSid()}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        if requestParameters.containsKey("user"):
            # Successful response from passport
            return self.authenticatePassportUser(configurationAttributes, requestParameters, step)

        elif requestParameters.containsKey("failure"):
            # This means that passport returned an error
            telemetry["result"] = "cancelled"
            duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)
            if step <= self.STEP_1FA: # User Cancelled during login
                self.telemetryClient.trackEvent("1FA Result", telemetry, {"durationInSeconds": duration})
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
            elif step == self.STEP_TOTP_REGISTER:
                self.telemetryClient.trackEvent("TOTP Registration Result", telemetry, {"durationInSeconds": duration}) 
                return False
            elif step == self.STEP_TOTP: # 2FA Failed. Redirect back to the RP
                self.telemetryClient.trackEvent("TOTP Authentication Result", telemetry, {"durationInSeconds": duration}) 
                return False
            else:
                print ("%s: Invalid passport failure in step %s." % (self.name, step))
                return False

        elif requestParameters.containsKey("lang"):
            # Manually selected language
            if requestParameters.containsKey("lang:en-CA"):
                locale = "en-CA"
            elif requestParameters.containsKey("lang:fr-CA"):
                locale = "fr-CA"
            else:
                return False
            languageBean.setLocaleCode(locale)
            sessionAttributes.put(AuthorizeRequestParam.UI_LOCALES, locale)

            langStep = ServerUtil.getFirstValue(requestParameters, "lang:step")

            return langStep == "lang"

        elif requestParameters.containsKey("chooser"):
            # Chooser page
            choice = self.getFormButton(requestParameters)
            telemetry["choice"] = choice
            self.telemetryClient.trackEvent("1FA choice made", telemetry, {"durationInSeconds": duration}) 

            provider = "gckey" if choice == "gckeyregister" else choice # Hack
            if provider in self.providers:
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
                # self.account.delete(identity.getWorkingParameter("userId"))
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
            if requestParameters.containsKey("secure:method"):
                method = ServerUtil.getFirstValue(requestParameters, "secure:method")
                telemetry["choice"] = method
                self.telemetryClient.trackEvent("2FA choice made", telemetry, {"durationInSeconds": duration}) 
                if method in self.mfaMethods:
                    if method in {"sms", "email"}:
                        identity.setWorkingParameter("oobChannel", method)
                else:
                    print ("%s: Invalid MFA method choice: %s." % (self.name, method))
                    return False
            else:
                addMessage("secure:select", FacesMessage.SEVERITY_ERROR, "sic.pleaseChoose")
                return False

        elif requestParameters.containsKey("result:continue"):
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
        rpConfig = self.rputils.getRPConfig(session)

        telemetry = {"sid" : session.getOutsideSid(),
                     "result" : "success"}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        externalProfile = self.passport.handleResponse(requestParameters)
        if externalProfile is None:
            return False
        provider = externalProfile["provider"]

        if identity.getWorkingParameter("userId") is None: # 1FA
            if provider not in self.providers:
                print ("Unauthorized provider: %s" % provider)
                return False

            if provider == "gckey" and identity.getWorkingParameter("provider") == "gckeyregister":
                telemetry["provider"] = "gckeyRegister"
            else:
                telemetry["provider"] = provider
            self.telemetryClient.trackEvent("1FA Result", telemetry, {"durationInSeconds": duration})

            provider = externalProfile["provider"]
            if provider not in self.providers:
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
                identity.setWorkingParameter("mfaMethod", self.account.getMfaMethod(user))
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

            if newUser:
                userService.addUser(user, True)
            elif userChanged:
                userService.updateUser(user)

            if self.getNextStep(configurationAttributes, requestParameters, self.STEP_1FA) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        elif provider == identity.getWorkingParameter("provider"): # Collection
            telemetry["provider"] = provider
            self.telemetryClient.trackEvent("Collection Result", telemetry, {"durationInSeconds": duration})

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
            client = self.rputils.getClient(session)
            if not self.account.getOpenIdSubject(user, client): # unless one already exists
                provider = identity.getWorkingParameter("provider")
                self.account.addOpenIdSubject(user, client, provider + nameId)

            if self.getNextStep(configurationAttributes, requestParameters, self.STEP_COLLECT) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        elif provider == rpConfig.get("mfaProvider"): # TOTP
            mfaId = identity.getWorkingParameter("mfaId")
            if externalProfile.get("externalUid").split(":", 1)[1] != mfaId:
                # Got the wrong MFA PAI.
                self.telemetryClient.trackEvent("SecurityEvent",
                                                {"cause": "mfaId mismatch"}, None)
                return False

            user = userService.getUser(identity.getWorkingParameter("userId"), "uid", "oxExternalUid", "locale")
            userChanged = False
            if self.account.getExternalUid(user, "mfa") is not None:
                step = self.STEP_TOTP
            else:
                step = self.STEP_TOTP_REGISTER

            telemetry["provider"] = provider
            event = "TOTP %s Result" % ("Authentication" if step == self.STEP_TOTP else "Registration")

            if step == self.STEP_TOTP_REGISTER:
                if self.totpTimeout and duration > self.totpTimeout:
                    # TOTP timed out
                    telemetry["result"] = "failed"
                    telemetry["reason"] = "timed out"
                    self.telemetryClient.trackEvent(event, telemetry, {"durationInSeconds": duration})
                    return False
                else:
                    self.account.addExternalUid(user, "mfa", mfaId)
                    identity.setWorkingParameter("mfaMethod", "totp")
                    userChanged = True

            telemetry["result"] = "success"
            self.telemetryClient.trackEvent(event, telemetry, {"durationInSeconds": duration})

            # Accept locale from the 2nd-factor CSP
            locale = externalProfile.get("locale")[0]
            if locale:
                languageBean.setLocaleCode(locale)
                if locale != user.getAttribute("locale", True, False):
                    user.setAttribute("locale", locale, False)
                    userChanged = True

            if userChanged:
                userService.updateUser(user)

            if self.getNextStep(configurationAttributes, requestParameters, step) < 0:
                return authenticationService.authenticate(identity.getWorkingParameter("userId"))

        return False

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
            httpRequest = facesResources.getExternalContext().getRequest()
            uiLocales = httpRequest.getParameter(AuthorizeRequestParam.UI_LOCALES)
        else:
            # Session exists.
            uiLocales = session.getSessionAttributes().get(AuthorizeRequestParam.UI_LOCALES)

        if uiLocales is not None:
            language = uiLocales[:2].lower()
        else:
            return "/lang.xhtml"

        if step == 1:
            if len(self.providers) > 1:
                step = self.STEP_CHOOSER
            else: # Direct pass-through
                step = self.STEP_1FA

        if step in {self.STEP_1FA, self.STEP_COLLECT, self.STEP_TOTP_REGISTER, self.STEP_TOTP, self.STEP_ABORT}: # Passport
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

        print ("Goto step %s" % step)

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
        rpConfig = self.rputils.getRPConfig(session)
        provider = identity.getWorkingParameter("provider")
        if provider == "gckeyregister": # Hack
            provider = "gckey"
        if provider is not None:
            providerInfo = self.passport.getProvider(provider)

        originalStep = step
        print ("Gluu step: %s" % originalStep)

        form = self.getFormName(requestParameters)
        if step == 1:
             # Determine if SPLASH, CHOOSER, or 1FA
            if requestParameters.containsKey("lang"):
                step = self.STEP_SPLASH
            elif requestParameters.containsKey("chooser") or requestParameters.containsKey("assertionResponse"):
                step = self.STEP_CHOOSER
            elif requestParameters.containsKey("user") or requestParameters.containsKey("failure"):
                step = self.STEP_1FA
        else:
            # Handle language toggles
            if requestParameters.containsKey("lang"):
                step = self.FORMS.get(ServerUtil.getFirstValue(requestParameters, "lang:step"))
                return self.gotoStep(step)
            # Determine the step from the form name (handles back button etc.)
            elif form in self.FORMS:
                step = self.FORMS.get(form)

        print ("Step %s, Form %s" % (step, form))

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
                if len(self.providers) == 1:
                    return self.gotoStep(self.STEP_ABORT)
                else:
                    return self.gotoStep(self.STEP_CHOOSER)
            elif requestParameters.containsKey("chooser"): # User double-clicked
                return self.gotoStep(self.STEP_1FA)
            elif identity.getWorkingParameter("userId") is not None:
                if providerInfo["GCCF"] and "collect" in rpConfig:
                    user = userService.getUser(identity.getWorkingParameter("userId"), "persistentId")
                    if self.account.getSamlSubject(user, rpConfig["collect"]) is None: # SAML PAI collection
                        return self.gotoStep(self.STEP_COLLECT)

        if step in {self.STEP_1FA, self.STEP_COLLECT}:
            if identity.getWorkingParameter("userId") is not None and self.mfaMethods:
                mfaMethodRegistered = identity.getWorkingParameter("mfaMethod")
                if mfaMethodRegistered is None:
                    if len(self.mfaMethods) == 1:
                        return self.gotoStep(self.STEP_TOTP_REGISTER) # Old behaviour
                    else:
                        return self.gotoStep(self.STEP_UPGRADE)
                elif mfaMethodRegistered == "fido":
                    return self.gotoStep(self.STEP_FIDO)
                elif mfaMethodRegistered == "totp":
                    return self.gotoStep(self.STEP_TOTP)
                elif mfaMethodRegistered in {"sms", "email"}:
                    return self.gotoStep(self.STEP_OOB)

        if step == self.STEP_OOB:
            if requestParameters.containsKey("oob:resend") or int(identity.getWorkingParameter("oobExpiry")) < Instant.now().getEpochSecond():
                return self.gotoStep(self.STEP_OOB)
            elif identity.getWorkingParameter("oobContact") is not None and identity.getWorkingParameter("mfaMethod") not in self.mfaMethods:
                return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_OOB_REGISTER:
            if identity.getWorkingParameter("oobCode"):
                return self.gotoStep(self.STEP_OOB)

        if step == self.STEP_UPGRADE:
            target = ServerUtil.getFirstValue(requestParameters, "secure:method")
            if target == "fido":
                return self.gotoStep(self.STEP_FIDO_REGISTER)
            elif target == "totp":
                return self.gotoStep(self.STEP_TOTP_REGISTER)
            elif target in {"email", "sms"}:
                return self.gotoStep(self.STEP_OOB_REGISTER)
            else:
                return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_REGISTER:
            if requestParameters.containsKey("registration:register"):
                if identity.getWorkingParameter("userId"):
                    return self.gotoStep(self.STEP_FIDO_REGISTER)
                else:
                    return self.gotoStep(self.STEP_REGISTER)
            else: # Cancel
                return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_TOTP:
            if requestParameters.containsKey("failure"): # User cancelled
                if len(self.providers) == 1:
                    return self.gotoStep(self.STEP_ABORT)
                else:
                    return self.gotoStep(self.STEP_CHOOSER)
            elif identity.getWorkingParameter("mfaMethod") not in self.mfaMethods:
                return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_TOTP_REGISTER:
            if requestParameters.containsKey("failure"): # User cancelled
                if len(self.mfaMethods) == 1 and identity.getWorkingParameter("mfaMethod") is None:
                    if len(self.providers) == 1:
                        return self.gotoStep(self.STEP_ABORT)
                    else:
                        return self.gotoStep(self.STEP_CHOOSER)
                else:
                    return self.gotoStep(self.STEP_UPGRADE)
            elif identity.getWorkingParameter("mfaMethod") not in self.mfaMethods:
                return self.gotoStep(self.STEP_UPGRADE)

        if step == self.STEP_FIDO_REGISTER:
            if requestParameters.containsKey("attestationResponse"):
                if ServerUtil.getFirstValue(requestParameters, "attestationResponse"):
                    return self.gotoStep(self.STEP_RESULT)
                else: # Failed
                    return self.gotoStep(self.STEP_UPGRADE)
            else: # Cancel
                if len(self.providers) == 1:
                    return self.gotoStep(self.STEP_ABORT)
                else:
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

def addMessage(uiControl, severity, msgId):
    languageBean = CdiUtil.bean(LanguageBean)
    facesResources = CdiUtil.bean(FacesResources)
    facesContext = facesResources.getFacesContext()
    externalContext = facesResources.getExternalContext()
    msgText = languageBean.getMessage(msgId)
    message = FacesMessage(severity, msgText, msgText)
    facesContext.addMessage(uiControl, message)
    externalContext.getFlash().setKeepMessages(True)

