const lcsApi = 'https://lang-canada.fjgc-gccf.gc.ca/v1/lang'

function getLanguage(callback) {
    $.ajax({
        url: lcsApi,
        type: 'GET',
        contentType: 'application/json',
        xhrFields: {
            withCredentials: true
        },
        success: function (data) { callback(data.lang) },
        error: function (jqXHR, textStatus, errorThrown) { console.log(errorThrown); callback(textStatus)}
    });
}

function setLanguage(language, callback) {
    $.ajax({
        url: lcsApi,
        type: 'PUT',
        datatype: 'application/json',
        contentType: 'application/json',
        data: JSON.stringify({lang: language}),
        xhrFields: {
            withCredentials: true
        },
        success: function (data) { callback(data.lang) },
        error: function (jqXHR, textStatus, errorThrown) { console.log(errorThrown); callback(textStatus)}
    });
}
