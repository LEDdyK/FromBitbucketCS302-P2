				/getonlineusers",
				data: {}
			}).done(function( o ) {
				//var someval = Math.floor(Math.random() * 100);
				$('#contacts_content').html(o);
			});
		}, 5000);//Delay here = 5 seconds
	}
);