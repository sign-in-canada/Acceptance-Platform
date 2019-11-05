var GLUU = (GLUU ? (function () { alert("GLUU already exists.") })() : {

    init: function () {
        console.log('ErrorValidation.js is ready!')

        ErrorValidation.Alert.init();


        $(document).on('submit', '#formArea', function () {

            GLUU.ValidatePassword();
            
        });

    },

    Alert: {

        init: function () {
            ErrorValidation.Alert.BindAction_Close();
        },
        _Placeholder: null,
        _HeadingTemplate: '<h3>{0}</h3>',
        _Template: '<section class="alert alert-{0} fade in" role="alert">{2}{1}</div>',
        _Display: function (clss, message, heading, target) {
            var alert = GLUU.Alert._Template.format(clss, message, (heading ? GLUU.Alert._HeadingTemplate.format(heading) : ""));
            if (!!target) {
                $(target).html(alert);
                $(target).focus();
            } else {
                GLUU.Alert._Placeholder.html(alert);
                GLUU.Alert._Placeholder.focus();
            }
        },
        BindAction_Close: function (trgt) {
            trgt = trgt || wb.doc;
            trgt.on("click", "button.gluu-alert-dismiss", GLUU.Alert.Dismiss);
        },
        Dismiss: function (event) {
            $(this).closest(".alert").remove();
        },
        Error: function (message, heading, target) {
            GLUU.Alert._Display("danger", message, heading, target);
        },
        Info: function (message, heading, target) {
            GLUU.Alert._Display("info", message, heading, target);
        },
        Success: function (message, heading, target) {
            GLUU.Alert._Display("success", message, heading, target);
        },
        Warning: function (message, heading, target) {
            GLUU.Alert._Display("warning", message, heading, target);
        }
    },
    ValidatePassword: function () {

        var pass = $('#pass').val();
        var conf = $('#conf').val();

        $('div #ErrorSection').attr('title', GLUU_Localization.Get('Close'));
        $('.wb-inv').innetText = GLUU_Localization.Get('Close');

        if (pass.length < 15) {

            var pElement = $('p');

            pElement.innetText = GLUU_Localization.Get('ErrorPasswordLength');
            $('errorMessage').append(pElement);

            return false;
        }
        
    }
});
