// Adding onClick to index elements, which is not possible with inline script due to default CSP of the Addon

var sel = document.getElementById('IPs');
var trut_btn = document.getElementById('trust_btn');
var untrust_btn = document.getElementById('untrust_btn');
var proxy_ip_input = document.getElementById('proxy_ip');

function isEmpty(obj){
    for(var key in obj) {
        if(obj.hasOwnProperty(key))
            return false;
    }
    return true;
}

// Filling the Multiple Select with the IPs trusted so far
function updateSelectOptions(){
	browser.storage.local.get("IPs")
	.then(function(elem){
		if(!isEmpty(elem)){

			var l = elem["IPs"];
			var select_options = "<option value='0'>select</option>";
			var n = l.length;
			for(var i = 0; i<n; i++){
				select_options += "<option value='" + i+1 + "'>"+l[i]+"</option>";
			}
			sel.innerHTML = select_options;
		}
	});

}
updateSelectOptions();	// As soon as the Addon starts, we fill the Multiple Select with the IPs trusted so far

// As soon as an IP is selected from the Dropdown Menu, it is written in the Input Text Field
sel.addEventListener('change', function(){
	proxy_ip_input.value = sel.options[sel.selectedIndex].text;
});

// Add to Trusted IPs the one specified in the Input Text Field
trust_btn.addEventListener('click', function(){
	
	var ip = proxy_ip_input.value;	// Getting IP from Input Text Field
	if(ip!=""){
		browser.storage.local.get("IPs")
		.then(function(elem){

			if(isEmpty(elem)){	// If the object with key "IPs" is not present, we have to initialize it
				var x = [];		// Empty Array
				x.push(ip);		// Array with the new IP
				var y = {};
				y["IPs"] = x;	// Building the new object where key is "IPs" and value is the Array with the new IP
				browser.storage.local.set(y);
				updateSelectOptions();
				console.log(browser.storage.local.get(["IPs"]));
			}
			else{
				var l = elem["IPs"];	// Elem is an object where there is the key "IPs" and the value is an Array
				if(!l.includes(ip)){	// We do not want duplicates
					l.push(ip);
					var y = {};
					y["IPs"] = l;
					browser.storage.local.set(y);
					updateSelectOptions();
				}
				console.log(browser.storage.local.get(["IPs"]));
			}
		});
	}

});

// Remove from Trusted IPs the one specified in the Input Text Field
untrust_btn.addEventListener('click', function(){
	var ip = proxy_ip_input.value;	// Getting IP from Input Text Field

	// Going to remove selected IP from trusted ones in local storage
	if(ip!=""){
		browser.storage.local.get("IPs")
		.then(function(elem){
			if(!isEmpty(elem)){
				var l = elem["IPs"];
				if(l.includes(ip)){
					var index = l.indexOf(ip);
					l.splice(index,1);
					var y = {};
					y["IPs"] = l;
					browser.storage.local.set(y);
					updateSelectOptions();
					proxy_ip_input.value = "";
				}
			}
		});
	}
});

var genkeypair = document.getElementById('genkeypair');
genkeypair.addEventListener('click', function() {
	entropy_collector();
});


var importPrK1Button = document.getElementById('importPrK1Button');
importPrK1Button.addEventListener('click', function() {
	importPrK1();
});

var importSrvPuKButton = document.getElementById('importSrvPuKButton');
importSrvPuKButton.addEventListener('click', function() {
	readServerPubKeyPkcs8();
});


var btnconnect = document.getElementById('btnconnect');
btnconnect.addEventListener('click', function() {
	ssh_connect();
});