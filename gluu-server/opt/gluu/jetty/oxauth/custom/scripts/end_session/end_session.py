#
# Authors: Doug Harris, Mustapha Radi
#

from org.gluu.model.custom.script.type.logout import EndSessionType
from org.gluu.util import StringHelper
from java.lang import String

class EndSession(EndSessionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "EndSession script. Initializing ..."
        print "EndSession script. Initialized successfully"

        return True

    def destroy(self, configurationAttributes):
        print "EndSession script. Destroying ..."
        print "EndSession script. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 11

    # Returns string, it must be valid HTML (with iframes according to spec http://openid.net/specs/openid-connect-frontchannel-1_0.html)
    # This method is called on `/end_session` after actual session is killed and oxauth construct HTML to return to RP.
    # Note :
    # context is reference of org.gluu.oxauth.service.external.context.EndSessionContext (in https://github.com/GluuFederation/oxauth project, )
    def getFrontchannelHtml(self, context):
        print "EndSession: getFrontchannelHtml called."
        
        notIssuedByPassport = context.getPostLogoutRedirectUri().lower().find("/passport/logout/response") == -1

        page = "<!DOCTYPE html>\n<html>\n<head>\n\t<script>\n" \
                "\t\twindow.onload = function() {\n"

        if notIssuedByPassport:
            page = page + "\t\t\tif (document.getElementById('passport').contentDocument.getElementsByTagName('body')[0].textContent == 'Success') { window.location.replace('" + context.getPostLogoutRedirectUri() + "')} else { window.location.replace('/oxauth/partial.htm') }\n\t\t}\n"
        else: 
            page = page + "\t\t\twindow.location.replace('" + context.getPostLogoutRedirectUri() + "');\n\t\t}\n"

        page = page + "\t\twindow.onerror = function() {\n" 

        if notIssuedByPassport:
            page = page + "\t\t\twindow.location.replace('/oxauth/partial.htm');\n\t\t}\n"
        else: 
            page = page + "\t\t\twindow.location.replace('/passport/logout/response/responder');\n\t\t}\n"

        page = page + "\t</script>\n" \
                "\t<title>Logout / D&eacute;connecter</title>\n" \
                "</head>\n" \
                "<body>\n" \
                "\t<img style='display:block;margin-left:auto;margin-right:auto;width:20;padding:10% 0;' src='/oxauth/ext/resources/assets/icon_flag_rotation_080x080.gif'/>\n"

        for frontchannelLogoutUri in context.getFrontchannelLogoutUris() :
            page = page + "\t<iframe height='0' width='0' src='%s' sandbox='allow-same-origin allow-scripts allow-popups allow-forms'></iframe>\n" % frontchannelLogoutUri

        if notIssuedByPassport:
            page = page + "\t<iframe id='passport' height='0' width='0' src='/passport/logout/request' sandbox='allow-same-origin allow-scripts allow-popups allow-forms'></iframe>\n"

        page = page + "</body>\n</html>"

        print "EndSession page: %s" % page

        return page