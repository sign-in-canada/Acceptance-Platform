var Cookie = {
    MaxByteSize: 2000,

    CreateCookie: function (name, value, days) {
        try {
            if (days) {
                var date = new Date();
                date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
                var expires = "; expires=" + date.toGMTString();
            }
            else {
                var expires = "";
            }

            var byteSize = Cookie.CheckCookieContentSize(value);
            if (byteSize > Cookie.MaxByteSize) {
                var valueLocation = '--InLocalStorage--';
                Cookie.SaveToLocalStorage(name, value);
                document.cookie = name + "=" + valueLocation + expires + "; path=/";
            } else {
                document.cookie = name + "=" + value + expires + "; path=/";
            }
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "CreateCookie", arguments);
        }
    },

    ReadCookie: function (name) {
        try {
            var nameEQ = name + "=";
            var cookieAttributes = document.cookie.split(';');
            for (var i = 0; i < cookieAttributes.length; i++) {
                var attribute = cookieAttributes[i];
                while (attribute.charAt(0) == ' ') {
                    attribute = attribute.substring(1, attribute.length);
                }
                if (attribute.indexOf(nameEQ) == 0) {
                    var value = attribute.substring(nameEQ.length, attribute.length);

                    if (value == '--InLocalStorage--') {
                        value = Cookie.ReadFromLocalStorage(name);
                        Cookie.ReadFromLocalStorage(name);
                    }

                    return value;
                }
            }
            return null;
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "ReadCookie", arguments);
        }
    },

    EraseCookie: function (name) {
        try {
            Cookie.CreateCookie(name, "", -1);
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "EraseCookie", arguments);
        }
    },

    SaveToLocalStorage: function (name, value) {
        try {
            localStorage.setItem(name, value);
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "SaveToLocalStorage", arguments);
        }
    },
    ReadFromLocalStorage: function (name) {
        try {
            var value;
            value = localStorage.getItem(name);
            return value;
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "ReadFromLocalStorage", arguments);
        }
    },
    RemoveFromLocalStorage: function (name) {
        try {
            localStorage.removeItem(name);
        } catch (errorThrown) {
            TBS_Error.JavaScriptError(errorThrown, "Cookie", "RemoveFromLocalStorage", arguments);
        }
    },

    CheckCookieContentSize: function byteLength(str) {
        // returns the byte length of an utf8 string
        var s = str.length;
        for (var i = str.length - 1; i >= 0; i--) {
            var code = str.charCodeAt(i);
            if (code > 0x7f && code <= 0x7ff) s++;
            else if (code > 0x7ff && code <= 0xffff) s += 2;
            if (code >= 0xDC00 && code <= 0xDFFF) i--; //trail surrogate
        }
        return s;
    }
}