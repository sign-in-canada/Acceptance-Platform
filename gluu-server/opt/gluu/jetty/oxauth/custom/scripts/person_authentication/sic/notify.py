# Module for Notify
#
# Author: Mustapha Radi

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.service.net import HttpService
from javax.ws.rs.core import Response

import sys
import java
import json

class NotifyError(Exception):
    """Base class for exceptions in this module."""
    pass

class Notify:

    def __init__(self):
        return None
    
    def init(self, configurationAttributes, scriptName):

        self.scriptName = scriptName
        print ("Notify. init called from " + self.scriptName)

        with open('/run/keyvault/secrets/NotifyKey', 'r') as f:
            self.notifyKey = f.read()

        if configurationAttributes.containsKey("oob_api_url"):
            self.apiUrl = configurationAttributes.get("oob_api_url").getValue2()

        if configurationAttributes.containsKey("oob_template_ids"):
            self.template_ids = json.loads(configurationAttributes.get("oob_template_ids").getValue2())

    def sendOobEmail(self, recipient, code):
        # Fail safely
        valid = False

        try:
            httpService = CdiUtil.bean(HttpService)
            httpclient = httpService.getHttpsClient()
            lang = CdiUtil.bean(LanguageBean).getLocale().getLanguage()

            apiKey = "ApiKey-v1 " + self.notifyKey
            apiUrl = self.apiUrl + "/email"
            template_id = self.template_ids["email-fr"] if lang == 'fr' else self.template_ids["email-en"]
            personalisation = '{"code":"' + code + '"}'

            # Prepare the post data
            postData = '{"email_address": "' + recipient + '", "template_id": "' + template_id + '", "personalisation": ' + personalisation + '}'
            headers = {"Authorization": apiKey, "Content-Type": "application/json"}

            # Execute the post request
            resultResponse = httpService.executePost(httpclient, apiUrl, "", headers, postData)
            httpResponse = resultResponse.getHttpResponse()
                
            # Validate if Notify has placed the message in a queue, ready to be sent to the provider.
            valid = (httpResponse.getStatusLine().getStatusCode() == Response.Status.CREATED.getStatusCode())
            
        except:
            message = "GCNotify Email sending Exception: " + str(sys.exc_info()[1])
            print ("SECURITY: %s" % message)

        return valid
    
    def sendOobSMS(self, recipient, code):
        # Fail safely
        valid = False

        try:
            httpService = CdiUtil.bean(HttpService)
            httpclient = httpService.getHttpsClient()
            lang = CdiUtil.bean(LanguageBean).getLocale().getLanguage()

            apiKey = "ApiKey-v1 " + self.notifyKey
            apiUrl = self.apiUrl + "/sms"
            template_id = self.template_ids["sms-fr"] if lang == 'fr' else self.template_ids["sms-en"]
            personalisation = '{"code":"' + code + '"}'

            # Prepare the post data
            postData = '{"phone_number": "' + recipient + '", "template_id": "' + template_id + '", "personalisation": ' + personalisation + '}'
            headers = {"Authorization": apiKey, "Content-Type": "application/json"}

            # Execute the post request
            resultResponse = httpService.executePost(httpclient, apiUrl, "", headers, postData)
            httpResponse = resultResponse.getHttpResponse()
                
            # Validate if Notify has placed the sms in a queue, ready to be sent to the provider.
            valid = (httpResponse.getStatusLine().getStatusCode() == Response.Status.CREATED.getStatusCode())
            
        except:
            message = "GCNotify SMS sending Exception: " + str(sys.exc_info()[1])
            print ("SECURITY: %s" % message)

        return valid