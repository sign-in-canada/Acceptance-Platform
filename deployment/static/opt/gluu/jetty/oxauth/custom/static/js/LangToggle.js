var LangTog = {
    Dictionary: [],
    DictionaryLoaded: false,
    LoadDictionaryMaxAttempts: 10,
    LoadDictionaryAttempts: 0,
    CurrentLanguage: "en",
	InProgress: false,
	CookieName: "GCFMLanguageCookie",
    
    Init: function(){
		
		$(document)
			.off('click', '.ToggleLanguage')
			.on('click', '.ToggleLanguage', function(event){LangTog.ToggleLanguage(false);});
	
	
		Loading.show();
		
		LangTog.InProgress = false;
		LangTog.LoadDictionaryAttempts = 0;
		LangTog.LoadDictionary();
		LangTog.LoadCurrentLanguageFromCookie();
        Loading.hide();
    },
	
	LoadCurrentLanguageFromCookie: function(){
		if(LangTog.DictionaryLoaded != true){
		    Loading.show();
			setTimeout(function(){
				Loading.hide();
				LangTog.LoadCurrentLanguageFromCookie();
			}, 500);
		} else {
			Loading.show();
			var cookieValue = Cookie.ReadCookie(LangTog.CookieName);
			if(cookieValue != null){
				if(cookieValue != LangTog.CurrentLanguage){
					LangTog.ToggleLanguage(true);
				} else {
					if(LangTog.CurrentLanguage == "en"){
						LangTog.CurrentLanguage = "fr";
					} else {
						LangTog.CurrentLanguage = "en";
					}
					LangTog.ToggleLanguage(true);	
				}
			} else {
				LangTog.CurrentLanguage = "fr";
				LangTog.UpdateCurrentLanguageInCookie();
				LangTog.ToggleLanguage(true);
			}
			Loading.hide();

		}
	},
	
	UpdateCurrentLanguageInCookie: function(){
		Cookie.EraseCookie(LangTog.CookieName);
		Cookie.CreateCookie(LangTog.CookieName, LangTog.CurrentLanguage, null);
	},
	
	ToggleLanguage: function(firstTime){
		if(LangTog.InProgress == true)
			return;
		LangTog.InProgress = true;
		if(LangTog.CurrentLanguage == "en"){
			LangTog.CurrentLanguage = "fr";
		} else {
			LangTog.CurrentLanguage = "en";
		}
		LangTog.StartResxLoad(firstTime);
		LangTog.UpdateCurrentLanguageInCookie();
		LangTog.InProgress = false;
	},

    LoadDictionary: function(){
        if(typeof LangDictionary === 'undefined' && LangTog.LoadDictionaryAttempts < LangTog.LoadDictionaryMaxAttempts ){
            Loading.show();
			LangTog.LoadDictionaryAttempts++;
            setTimeout(function(){
				Loading.hide();
				LangTog.LoadDictionary();
			}, 500);
        } else if(typeof LangDictionary === 'undefined' && LangTog.LoadDictionaryAttempts >= LangTog.LoadDictionaryMaxAttempts ){
            Loading.show();
			alert("could not load dictionary");
			Loading.hide();
        } else {
            Loading.show();
			LangTog.Dictionary = LangDictionary;
            LangTog.DictionaryLoaded = true;
			Loading.hide();
        }
		
    },

    StartResxLoad: function(firstTime){
		
        if(LangTog.DictionaryLoaded == false){
			Loading.show();
            setTimeout(function(){
				Loading.hide();
				LangTog.StartResxLoad();
			}, 500);
        } else {
			Loading.show();
            var langObjects = $('.langToggle');

            $.each(langObjects, function(index, object){
				LangTog.SwapLanguage(object);
            });
			
			var tranObjects = $('.transToggle');
			$.each(tranObjects, function(index, object){
				LangTog.TranslateLanguage(object, firstTime);
            });
			
			Loading.hide();
        }
		
		
    },

	SwapLanguage: function(objectLang){
		var langId = $(objectLang).attr('data-langId');
		var resource = LangTog.GetDictionaryValue(langId);
		//$(objectLang).replaceWith(resource);
		if($(objectLang).is("input")){
			$(objectLang)[0].value = resource;
		}
		else {
			$(objectLang)[0].innerHTML = resource;
		}
	},
	
	
	TranslateLanguage: function(objectTrans, firstTime){
		var langId = $(objectTrans).attr('data-langId');
		var resourceItem = LangTog.GetDictionaryItem(langId);
		if($(objectTrans).is("input")){
			$(objectTrans)[0].value = LangTog.TranslateSentence($(objectTrans)[0].value, resourceItem, firstTime);
		}
		else {
			$(objectTrans)[0].innerHTML = LangTog.TranslateSentence($(objectTrans)[0].innerHTML, resourceItem, firstTime);
		}
		
		

	},

	TranslateSentence: function(sentence, resourceItem, firstTime){
		
		if(firstTime != null && firstTime == true &&  LangTog.CurrentLanguage == "fr"){
			sentence = sentence.replace(resourceItem.en, resourceItem.fr);
		} else if(LangTog.CurrentLanguage == "en"){
			sentence = sentence.replace(resourceItem.fr, resourceItem.en);
		} else {
			sentence = sentence.replace(resourceItem.en, resourceItem.fr);
		}
		
		return sentence;
	},
	
    GetDictionaryItem: function(langId){
        if(LangTog.Dictionary == null || LangTog.Dictionary.length <= 0)
            return null;
        for(var i = 0; i < LangTog.Dictionary.length; i++){
            if(LangTog.Dictionary[i].id == langId)
            return LangTog.Dictionary[i];
        }
        return null;
    },

	
    GetDictionaryValue: function(langId){
        var resourceObject = LangTog.GetDictionaryItem(langId);
        
        if(resourceObject != null){
            if(LangTog.CurrentLanguage == "en" && resourceObject.en != null){
                return resourceObject.en;
            } else if(LangTog.CurrentLanguage == "fr" && resourceObject.fr != null){
                return resourceObject.fr;
            }  
        }  
        return "No Lang Object";
        
    } 

}



