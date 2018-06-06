$(document).ready(
	function() {
		setInterval(function() {
			var ipText = document.getElementById('ip').textContent;
			var portText = document.getElementById('port').textContent;
			var head = "http://";
			var sep = ":"
			var API1 = "/getonlineusers?item=username";
			var API2 = "/checkStatus";
			var API3 = "/getBoard";
			var API4 = "/getLatest";
			$.ajax({
				type: "POST",
				url: head.concat(ipText.concat(sep.concat(portText.concat(API1)))),
				data: {}
			}).done(function(o) {
				$('#contacts_content').html(o);
			});
			$.ajax({
				type: "POST",
				url: head.concat(ipText.concat(sep.concat(portText.concat(API2)))),
				data: {}
			}).done(function(o) {
				$('.status').html(o);
			});
			$.ajax({
				type: "POST",
				url: head.concat(ipText.concat(sep.concat(portText.concat(API3)))),
				data: {}
			}).done(function(o) {
				$('#board_content').html(o);
			});
			$.ajax({
				type: "POST",
				url: head.concat(ipText.concat(sep.concat(portText.concat(API4)))),
				data: {}
			}).done(function(o) {
				$('#latest_content').html(o);
			});
		}, 5000);//Delay here = 5 seconds
	}
);