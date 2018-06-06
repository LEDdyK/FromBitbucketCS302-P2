$(document).ready(
	function() {
		setInterval(function() {
			var ipText = document.getElementById('ip').textContent;
			var portText = document.getElementById('port').textContent;
			var head = "http://";
			var sep = ":"
			var API1 = "/getonlineusers?item=all";
			$.ajax({
				type: "POST",
				url: head.concat(ipText.concat(sep.concat(portText.concat(API1)))),
				data: {}
			}).done(function(o) {
				onlinelist = o.split('\n')
				var i;
				for (i = 1; i < o.length; i++) {
					entry = onlinelist[i].split(',')
					document.getElementById(entry[0]).disabled = false;
				}
			});
		}, 1000);//Delay here = 5 seconds
	}
);
</script>
<script language="javascript">
	function autoFill() {
		document.getElementsByName('ip').value = "My Text Input";
		document.getElementsByName('port').value = "My Text Input";
		document.getElementsByName('receiver').value = "Dropdown2";
	}