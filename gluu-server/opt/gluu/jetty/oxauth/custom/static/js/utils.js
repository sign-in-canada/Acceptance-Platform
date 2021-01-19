
$(document).ready(function() {
	$( "#reportPbSubmit" ).click(function() {
		var form = $(this).parents('form');
   		$.ajax({
        		url:  form.attr('action'),
        		type: "POST",
        		dataType: "text",
        		data:  form.serialize()
        		//error: function (xhr, ajaxOptions, thrownError) {console.log(thrownError);}
    		});
	});
});
