// mark all external links' target to '_blank' 
/* removed in favor of the modal popup - remove if not seen as needed any longer
function externalLinks() {
	if (!document.getElementsByTagName) return;
	var anchors = document.getElementsByTagName("a");
	for (var i=0; i < anchors.length; i++) {
		var anchor = anchors[i];
		if (anchor.getAttribute("href") && anchor.getAttribute("rel") == "external") {
			anchor.target = "_blank";
		}
		if (anchor.getAttribute("href") && anchor.getAttribute("rel") == "top") {
			anchor.target = "_top";
		}
	}
}
*/

$(function() {
	// removed as part of removing the above code
	//externalLinks();
	
	var $external_vac_view_iframe = $('#vac-site-popup-frame'),
	    $external_vac_links = $('.external-vac-link');
	
	// links with external-vac-link class when clicked will attempt to open any data-vac-urls using WET's lightbox plugin
	// this is intended to work with the Full-screen overlay which can be seen at: http://wet-boew.github.io/v4.0-ci/demos/overlay/overlay-en.html
	$external_vac_links.click(function(e){
	    var $this = $(this), 
		    url = $this.attr('data-vac-url');
		  
		if (url)
		{			
			$external_vac_view_iframe.attr('src', url);
	    }
	});	
	
	$external_vac_links.on('setfocus.wb', function(e) {		
		$('#vac-site-popup iframe').remove();
		// recreate the frame to remove the blink when loading another link on the same page.
		$('#vac-site-popup').append('<iframe id="vac-site-popup-frame" sandbox="allow-same-origin allow-scripts" src="about:blank" frameborder="0"></iframe>');
		$external_vac_view_iframe = $('#vac-site-popup-frame');
	});
	
	// mark all rel="top" links' target
	$('a[rel="top"]').attr('target', '_top');
	
	// find all rel="external" links - add a click handler to preview the link in a modal with a continue button 
	$('a[rel="external"]').unbind().click(function(e)
	{	
		var $this = $(this), 
            url = $this.attr('data-vac-url');
	
	    $('#vac-site-confirm-popup-link').attr('href', url);
	});

//	$('[data-external-url]').click(function(e) {
//
//		var url = $(this).attr('data-external-url');
//
//		$('#vac-site-confirm-popup-link').attr('href', url);
//
//		$(document).trigger("open.wb-lbx", [[{ src: "#vac-site-confirm-popup", type: "inline", overflowY: "hidden" }], true]);
//	});
	
	$('body').on('click vclick', '[data-external-url]', function(e){
		
		var url = $(this).attr('data-external-url');

		$('#vac-site-confirm-popup-link').attr('href', url);

		$(document).trigger("open.wb-lbx", [[{ src: "#vac-site-confirm-popup", type: "inline", overflowY: "hidden" }], true]);
	});

	
	$('[data-show-spinner-modal-on-click]').click(function(e){
	  $(document).trigger("open.wb-lbx", [[{ src: "#spinner-modal", type: "inline", overflowY: "hidden" }], true]);
	});
	
	$('[data-show-upload-spinner-modal-on-click]').click(function(e){
	  $(document).trigger("open.wb-lbx", [[{ src: "#spinner-modal-uploading", type: "inline", overflowY: "hidden" }], true]);
	});
});
