function initHandler() {
  
}


function addWBReadyEventListener_FP() {

    //Wet has not even initialized
    if (typeof wb === 'undefined') {
        setTimeout(function () { addWBReadyEventListener_FP(); }, 100);
    } else {
        //event to listen to WET ready event
        wb.doc.on("wb-ready.wb", function (evt) {
            initHandler();
        });

        //if Wet Event has fired already, this will detect that and trigger init
        if ($._data(document, "events")["wb-ready"].length >= 2) {
            initHandler();
        }
    }
}

addWBReadyEventListener_FP();