StringArray = Java.type("java.lang.String[]");

var logger = Java.type("org.slf4j.LoggerFactory").getLogger("net.shibboleth.idp.attribute");

var recipientId = resolutionContext.getAttributeRecipientID();
logger.debug("Attribute Recipient ID {} ", recipientId);

var transientIds = transientId.getValues().toArray(new StringArray(0));
if (transientIds.length === 1 && transientIds[0].startsWith("[")) {
   transientIds = transientIds[0].slice(1, -1).split(', ');
}

for each (transientIdValue in transientIds) {
   var matches = transientIdValue.match(/([^\|]+)\|(\d+)\|([^\|]+)\|(.*)/);
   if (matches === null) { // Skip garbage
      logger.error("Malformed value for transientId: {}", transientIdValue);
      continue;
   }
   var rpEntity = matches[1];
   var expiry = parseInt(matches[2]) * 1000 + 300000;
   var claimsURL = matches[3];
   var accessToken = matches[4];

   logger.debug("Found access token for {} with expiry {}", rpEntity, new Date(expiry));
   if (rpEntity === recipientId && new Date().getTime() <= expiry) {
      logger.debug("Populating a value for the userInfo reference {}", claimsURL);
      claimSource.addValue(claimsURL + "|" + accessToken);
      break;
   }
}
