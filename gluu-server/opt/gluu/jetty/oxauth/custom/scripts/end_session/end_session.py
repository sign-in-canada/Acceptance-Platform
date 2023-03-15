#
# Authors: Doug Harris, Mustapha Radi
#

from org.gluu.model.custom.script.type.logout import EndSessionType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service.common import EncryptionService

from org.apache.commons.lang3 import StringUtils

import json
import time
class EndSession(EndSessionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        self.name = customScript.getName()

        self.pageTemplate = ("<!DOCTYPE html>"
                         + "<html>"
                         +    "<head>"
                         +    "<title>Logout / D&eacute;connecter</title>"
                         +       "<script>"
                         +           "const rp_initiated = %s;"
                         +           "const passport_logout = %s;"
                         +           "const post_logout_redirect_uri = '%s';"
                         +           "window.onload = function() {"
                         +              "if (passport_logout) {"
                         +                 "if (rp_initiated) {"
                         +                    "passportResponse = document.getElementById('passport').contentDocument.getElementsByTagName('body')[0].textContent;"
                         +                    "if (passportResponse === 'Success') {"
                         +                       "window.location.replace(post_logout_redirect_uri)"
                         +                     "} else {"
                         +                        "window.location.replace('/oxauth/partial.htm')"
                         +                     "}"
                         +                 "} else {"
                         +                     "window.location.replace('/passport/logout/response/Success')"
                         +                 "}"
                         +              "} else {"
                         +                 "window.location.replace(post_logout_redirect_uri)"
                         +              "}"
                         +           "};"
                         +           "window.onerror = function() {"
                         +              "if (passport_logout && rp_initiated) {"
                         +                 "window.location.replace('/passport/logout/response/Responder')"
                         +              "} else {"
                         +                 "window.location.replace('/oxauth/partial.htm')"
                         +              "}"
                         +           "}"
                         +       "</script>"
                         +    "</head>"
                         +    "<body>"
                         +       "<img style='display:block;margin-left:auto;margin-right:auto;width:20;padding:10%% 0;' src='/oxauth/ext/resources/assets/icon_flag_rotation_080x080.gif'/>"
                         +       "%s"
                         +    "<body>"
                         + "<html>")

        self.iframeTemplate = "<iframe height='0' width='0' src='%s' sandbox='allow-same-origin allow-scripts allow-popups allow-forms'></iframe>"

        print ("%s: Initialized successfully." % self.name)
        return True

    def destroy(self, configurationAttributes):
        print ("%s: Destroyed successfully." % self.name)
        return True

    def getApiVersion(self):
        return 11

    # Returns string, it must be valid HTML (with iframes according to spec http://openid.net/specs/openid-connect-frontchannel-1_0.html)
    # This method is called on `/end_session` after actual session is killed and oxauth construct HTML to return to RP.
    # Note :
    # context is reference of org.gluu.oxauth.service.external.context.EndSessionContext (in https://github.com/GluuFederation/oxauth project, )
    def getFrontchannelHtml(self, context):
        sessionAttributes = context.getSessionId().getSessionAttributes()
        postLogoutRedirectUri = context.getPostLogoutRedirectUri()
        passportLogout = sessionAttributes.get("persistentId") is not None
        rpInitiated  = postLogoutRedirectUri.lower().find("/passport/logout/response") == -1
        iframes = []

        for frontchannelLogoutUri in context.getFrontchannelLogoutUris():
            iframes.append(self.iframeTemplate % frontchannelLogoutUri)

        if passportLogout and rpInitiated:
            iframes.append("<iframe id='passport' height='0' width='0' src='%s' sandbox='allow-same-origin allow-scripts allow-popups allow-forms'></iframe>" % self.getPassportRequest(sessionAttributes))

        page = self.pageTemplate % ("true" if rpInitiated else "false", "true" if passportLogout else "false", postLogoutRedirectUri, " ".join(iframes))
        return page

    def getPassportRequest(self, sessionAttributes):
        persistentId = sessionAttributes.get("persistentId")
        spNameQualifier, nameQualifier, nameId = tuple(persistentId.split("|"))

        params = {"provider": sessionAttributes.get("SAMLProvider"),
                  "nameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                  "nameID": nameId,
                  "sessionIndex": sessionAttributes.get("sessionIndex"),
                  "exp": int(time.time()) + 60}

        if nameQualifier != "undefined":
            params["nameQualifier"] = nameQualifier

        if spNameQualifier != "undefined":
            params["spNameQualifier"] = spNameQualifier

        jsonParams = json.dumps(params)
        encryptedParams = CdiUtil.bean(EncryptionService).encrypt(jsonParams)
        # Need to translate from base64 to base64url to make it URL-friendly for passport
        # See RFC4648 section 5
        encodedParams = StringUtils.replaceChars(encryptedParams, "/+", "_-")

        return "/passport/logout/request/" + encodedParams
