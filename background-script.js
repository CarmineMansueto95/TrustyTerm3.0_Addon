browser.browserAction.onClicked.addListener(clickListener);

function clickListener() {

	console.log(browser.permissions.getAll());
	/*const permissionsToRequest = {origins: ["https://192.168.56.102/*"]}
	browser.permissions.request(permissionsToRequest)
	.then(function(response){
		console.log(response);
		console.log(browser.permissions.getAll());
	})*/

	startNewSession();
}

function startNewSession(){

	// Creating new tab, loading index.html in the new tab and synchronously load all the scripts in /MyScripts

	var creating = browser.tabs.create({"url":"/index.html"});
	creating.then(function(tab) {

		var p1 = browser.tabs.insertCSS(tab.Id, {
			file: "/MyScripts/xterm3.4.15.css"
		});
		p1.then(function(){
			var p2 = browser.tabs.executeScript(tab.Id, {
				file: "/MyScripts/xterm3.4.15.js"
			});
			p2.then(function(){
				var p3 = browser.tabs.executeScript(tab.Id, {
					file: "/MyScripts/jsbn.js"
				});
				p3.then(function(){
					var p4 = browser.tabs.executeScript(tab.Id, {
						file: "/MyScripts/jsbn2.js"
					});
					p4.then(function(){
						var p5 = browser.tabs.executeScript(tab.Id, {
							file: "/MyScripts/tt_rng.js"
						});
						p5.then(function(){
							var p6 = browser.tabs.executeScript(tab.Id, {
								file: "/MyScripts/rsa.js"
							});
							p6.then(function(){
								var p7 = browser.tabs.executeScript(tab.Id, {
									file: "/MyScripts/rsa2.js"
								});
								p7.then(function(){
									var p8 = browser.tabs.executeScript(tab.Id, {
										file: "/MyScripts/base64.js"
									});
									p8.then(function(){
										var p9 = browser.tabs.executeScript(tab.Id, {
											file: "/MyScripts/seedrandom.js"
										});
										p9.then(function(){
											var p10 = browser.tabs.executeScript(tab.Id, {
												file: "/MyScripts/jsencrypt.js"
											});
											p10.then(function(){
												var p11 = browser.tabs.executeScript(tab.Id,{
													file: "/MyScripts/jsencrypt.min.js"
												});
												p11.then(function(){
													var p12 = browser.tabs.executeScript(tab.Id, {
														file: "/MyScripts/sha3.js"
													});
													p12.then(function(){
														var p13 = browser.tabs.executeScript(tab.Id, {
															file: "/MyScripts/sha3.min.js"
														});
														p13.then(function(){
															var p14 = browser.tabs.executeScript(tab.Id, {
																file: "/MyScripts/jsrsasign.js"
															});
															p14.then(function(){
																var p15 = browser.tabs.executeScript(tab.Id, {
																	file: "/MyScripts/rsa2pem.js"
																});
																p15.then(function(){
																	var p16 = browser.tabs.executeScript(tab.Id, {
																		file: "/MyScripts/pem2rsa.js"
																	});
																	p16.then(function(){
																		var p17 = browser.tabs.executeScript(tab.Id, {
																			file: "/MyScripts/rsadigestsign.js"
																		});
																		p17.then(function(){
																			var p18 = browser.tabs.executeScript(tab.Id, {
																				file: "/MyScripts/MochiKit.js"
																			});
																			p18.then(function(){
																				var p19 = browser.tabs.executeScript(tab.Id, {
																					file: "/MyScripts/trustyterm.js"
																				});
																				p19.then(function(){
																					var p20 = browser.tabs.executeScript(tab.Id, {
																						file: "/MyScripts/trusted_webbased_ssh.js"
																					});
																					p20.then(function(){
																						browser.tabs.executeScript(tab.Id, {
																							file: "/index-setup.js"
																						});
																					});
																				});
																			});
																		})
																	});
																});
															});
														});
													});
												});
											});
										});
									});
								});
							});
						});
					});
				});
			});
		});
	});
	
}