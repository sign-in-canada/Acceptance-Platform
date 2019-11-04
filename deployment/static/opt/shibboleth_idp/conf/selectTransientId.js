var logger = Java.type("org.slf4j.LoggerFactory").getLogger("net.shibboleth.idp.attribute");

var recipientId = resolutionContext.getAttributeRecipientID();
logger.info("Attribute Recipient ID {} ", recipientId);

var transientIds = transientId.getValues().iterator();

while (transientIds.hasNext()) {
   var transientIdValue = transientIds.next();
   var matches = transientIdValue.match(/([^\|]+)\|(\d+)\|([^\|]+)\|(.*)/);
   if (matches === null) { // Skip garbage
      logger.error("Malformed value for transientId: {}", transientIdValue);
      continue;
   }
   var rpEntity = matches[1];
   var expiry = parseInt(matches[2]) * 1000 + 300000;
   var claimsURL = matches[3];
   var accessToken = matches[4];

   logger.info("Found access token for {} with expiry {}", rpEntity, new Date(expiry));
   if (rpEntity === recipientId && new Date().getTime() <= expiry) {
      logger.info("Populating a value for the userInfo reference {}", claimsURL);
      userInfo.addValue(claimsURL + "|" + accessToken);
      break;
   }
}
