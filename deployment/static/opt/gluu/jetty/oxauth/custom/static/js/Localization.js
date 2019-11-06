/* ---------------------------------------------------------------------------------------------------------------------------------
-- MPT  09/04/2019   -- Creation of the Javascript Resources file.
--
-- DESCRIPTION:     This localization files can be use to create global resources reference. Same purpose as the GlobalResources.resx. 
-- 
-- REFERENCE:       https://stackoverflow.com/questions/1168807/how-can-i-add-a-key-value-pair-to-a-javascript-object 
--                  http://pietschsoft.com/post/2015/09/05/JavaScript-Basics-How-to-create-a-Dictionary-with-KeyValue-pairs 
--
-- //CREATE OBJECT: 
--          var dictionaryName = new Object();
--              OR
--          var dictionaryName = { Key1 : "Value1", Key2 : "Value2"};
-- 
-- //POPULATE VALUES:
--          dictionaryName["one"] = 1;
--          dictionaryName[1] = "Hello";
--              OR 
--          //(By properties)
--          dictionaryName.Firstname = "John";
--          dictionaryName.Lastname = "Doe";
--
-- //ITERATING KEY/VALUE PAIR:
--          for(var key in dictionaryName){
--              var value = dictionaryName[Key];
--              // ...
--          }
--
-- //ACCESS KEY/VALUE PAIRS DIRECTLY:
--          //(By indexer)
--          var name = dictionaryName["Firstname"];
--              OR 
--          //(By properties)
--          var name = dictionaryName.Firstname;
--
-- //FUNCTION AS KEY OR VALUES:
--          var dictionaryName = {};
--          var fn = function(){ //... };
--
--          //(Set the function as Value)
--          dictionaryName["fn"] = fn;
--
--          //(Set the function as Key)
--          dictionaryName[fn] = "Value1";
--          var method = dictionaryName.fn;
--
-- ---------------------------------------------------------------------------------------------------------------------------------
*/

var GLUU_Localization = {

    _lang: function () {
        return $("html")[0].lang || "en";

    },
    Dictionary: {
        Error: { en: 'Error', fr: 'Erreur' },
        Close: { en: 'Close', fr: 'Fermer' },
        ErrorPasswordLength: { en: 'Minimum of 15 characters.', fr: 'Minimum de 15 caractères.' },
        ErrorPasswordCompare: { en: 'The confirmation password doesn\'t match.', fr: 'Le mot de passe de confirmation est différent.' }

    },
    Get: function (key) {
        return EEPR_Localization.Dictionary[key][EEPR_Localization._lang()];

    }

};

$(document).on('ready', function () {
    var GLUU_Localization = GLUU_Localization;
    console.log('Localization.js var GLUU_Localization is ready!')
});/* ---------------------------------------------------------------------------------------------------------------------------------
-- MPT  09/04/2019   -- Creation of the Javascript Resources file.
--
-- DESCRIPTION:     This localization files can be use to create global resources reference. Same purpose as the GlobalResources.resx. 
-- 
-- REFERENCE:       https://stackoverflow.com/questions/1168807/how-can-i-add-a-key-value-pair-to-a-javascript-object 
--                  http://pietschsoft.com/post/2015/09/05/JavaScript-Basics-How-to-create-a-Dictionary-with-KeyValue-pairs 
--
-- //CREATE OBJECT: 
--          var dictionaryName = new Object();
--              OR
--          var dictionaryName = { Key1 : "Value1", Key2 : "Value2"};
-- 
-- //POPULATE VALUES:
--          dictionaryName["one"] = 1;
--          dictionaryName[1] = "Hello";
--              OR 
--          //(By properties)
--          dictionaryName.Firstname = "John";
--          dictionaryName.Lastname = "Doe";
--
-- //ITERATING KEY/VALUE PAIR:
--          for(var key in dictionaryName){
--              var value = dictionaryName[Key];
--              // ...
--          }
--
-- //ACCESS KEY/VALUE PAIRS DIRECTLY:
--          //(By indexer)
--          var name = dictionaryName["Firstname"];
--              OR 
--          //(By properties)
--          var name = dictionaryName.Firstname;
--
-- //FUNCTION AS KEY OR VALUES:
--          var dictionaryName = {};
--          var fn = function(){ //... };
--
--          //(Set the function as Value)
--          dictionaryName["fn"] = fn;
--
--          //(Set the function as Key)
--          dictionaryName[fn] = "Value1";
--          var method = dictionaryName.fn;
--
-- ---------------------------------------------------------------------------------------------------------------------------------
*/

var GLUU_Localization = {

    _lang: function () {
        return $("html")[0].lang || "en";

    },
    Dictionary: {
        Error: { en: 'Error', fr: 'Erreur' },
        Close: { en: 'Close', fr: 'Fermer' },
        ErrorPasswordLength: { en: 'Minimum of 15 characters.', fr: 'Minimum de 15 caractères.' },
        ErrorPasswordCompare: { en: 'The confirmation password doesn\'t match.', fr: 'Le mot de passe de confirmation est différent.' }

    },
    Get: function (key) {
        return EEPR_Localization.Dictionary[key][EEPR_Localization._lang()];

    }

};

$(document).on('ready', function () {
    var GLUU_Localization = GLUU_Localization;
    console.log('Localization.js var GLUU_Localization is ready!')
});
