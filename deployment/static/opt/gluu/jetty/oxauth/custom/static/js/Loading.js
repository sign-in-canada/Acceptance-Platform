var Loading = {
    _Placeholder: null,
    _OverLay_Placeholder: null,
    PlaceHolderIdentifier: null,
    OverLayPlaceHolderIdentifier: null,
    loadingCount: null,

    Init: function (config) {
        if (config != null)
            Loading.SetConfig(config);
        else
            Loading.SetDefault();

        Loading._Placeholder = $(Loading.PlaceHolderIdentifier);
        Loading._OverLay_Placeholder = $(OverLayPlaceHolderIdentifier);
        Loading.loadingCount = 0;

        if (!!Loading._Placeholder.length) {
            Loading._Placeholder.hide();
            Loading._OverLay_Placeholder.hide();
        }
    },

    SetDefault: function () {
        if (Loading.PlaceHolderIdentifier == null)
            Loading.PlaceHolderIdentifier = "#loading";

        if (Loading.OverLayPlaceHolderIdentifier == null)
            Loading.OverLayPlaceHolderIdentifier = "#loading-overlay";
    },

    SetConfig: function (config) {
        if (config.PlaceHolderIdentifier != null)
            Loading.PlaceHolderIdentifier = config.PlaceHolderIdentifier;

        if (config.OverLayPlaceHolderIdentifier != null)
            Loading.OverLayPlaceHolderIdentifier = config.OverLayPlaceHolderIdentifier;

        Loading.SetDefault();
    },

    hide: function () {
        Loading.loadingCount--;
        if (Loading.loadingCount <= 0) {
            Loading.loadingCount = 0;
            Loading._OverLay_Placeholder.hide();
            Loading._Placeholder.hide();
        }
    },

    show: function () {
        Loading.loadingCount++;
        Loading._OverLay_Placeholder.show();
        Loading._Placeholder.show();
    }
}