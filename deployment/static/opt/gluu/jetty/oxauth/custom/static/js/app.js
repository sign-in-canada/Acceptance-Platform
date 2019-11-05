var mva_app = {
  initializeFontAwesome : function() {
    $('.fa').attr('aria-hidden', 'true');
  },

  removeAbbreviation : function(textP) {
    return textP.replace(/<abbr[^'"]*['"]|['"].*?abbr>/ig, "");
  },
  
  updateQueryStringParameter : function(uriP, keyP, valueP) {
    var regex = new RegExp("([?&])" + keyP + "=.*?(&|#|$)", "i");
    var uri = String(uriP);
    
    if (uri.match(regex)) {
      return uri.replace(regex, '$1' + keyP + "=" + valueP + '$2');
    } 
    
    var hash =  '';
    if( uri.indexOf('#') !== -1 ) {
        hash = uri.replace(/.*#/, '#');
        uri = uri.replace(/#.*/, '');
    }
    var separator = (uri.indexOf('?') !== -1) ? "&" : "?";    
    return uri + separator + keyP + "=" + valueP + hash;
  },
  
  swapLanguage : function() {
    var new_lang = 'en_CA';
    var current_lang = $('html').prop('lang');
    
    if (current_lang == 'en' || current_lang == 'en_CA') {
      new_lang = 'fr_CA';
    }
    
    document.location = mva_app.updateQueryStringParameter(document.location, 'request_locale', new_lang); 
  }

};

$(function() {
  mva_app.initializeFontAwesome();
});
