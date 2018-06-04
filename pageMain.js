$(document).ready(
	function() {
		setInterval(function() {
			$.ajax({
				type: "POST",
				url: "http://192.168.1.75:10000/getonlineusers",
				data: {}
			}).done(function( o ) {
				//var someval = Math.floor(Math.random() * 100);
				$('#contacts_content').html(o);
			});
		}, 5000);//Delay here = 5 seconds
	}
);
$(document).ready(
	function() {
		setInterval(function() {
		var someval = Math.floor(Math.random() * 100);
		$('#sample').text('Test' + someval);
		}, 5000);//Delay here = 5 seconds 
	}
);