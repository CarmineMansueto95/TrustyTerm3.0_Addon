browser.browserAction.onClicked.addListener(clickListener);

// When the user clicks on the Add-on icon, this function is fired
function clickListener() {
	
	// Creating new tab, loading index.html in the new tab and sequentially load all the scripts in /MyScripts
	var creating = browser.tabs.create({"url":"/index.html"});
	creating.then(function(tab) {
		browser.tabs.insertCSS(tab.Id, {file: "/MyScripts/xterm3.4.15.css"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/xterm3.4.15.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/jsbn.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/jsbn2.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/tt_rng.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/rsa.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/rsa2.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/base64.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/seedrandom.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/jsencrypt.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/jsencrypt.min.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/sha3.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/sha3.min.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/jsrsasign.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/rsa2pem.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/pem2rsa.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/rsadigestsign.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/MochiKit.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/trustyterm.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/MyScripts/trusted_webbased_ssh.js"})
		.then(function(){ browser.tabs.executeScript(tab.Id, {file: "/index-setup.js"});
		}); });	});	}) }); }); }); }); }); }); }); }); }); }); }); }); }); }); }); });
	});
	
}