/*
* NAME: trusted_webbased_ssh.js
* AUTHOR: Mirko Di Silvio
* DEPENDS ON:
*  Tom Wu's (http://www-cs-students.stanford.edu/~tjw/jsbn/)
*   jsbn.js - basic BigInteger implementation
*  	jsbn2.js - the rest of the library, including most public BigInteger methods
*  	rsa - implementation of RSA encryption, does not require jsbn2.js
*  	rsa2 - rest of RSA algorithm, including decryption and keygen
*  	base64 - Base64 encoding and decoding routines
*  Mirko Di Silvio's
*  	rsa2pem.js - encode private key in PEM format and public key in openssh format
*  	pem2rsa.js - RSAKey class extension to read PKCS#1 RSA private key PEM file
*  	rsadigestsign.js - RSAKey class extension to sign a digest with RSA private key
*  	trustyterm.js - client side terminal emulation
*   tt_rng.js - Seeded RNG interface
*  David Bau's (http://davidbau.com/archives/2010/01/30/random_seeds_coded_hints_and_quintillions.html)
*  	seedrandom.js - seedable random number generator
*  Javascript framework
* 	MochiKit.js - light-weight JavaScript library
*
*/

//GLOBALS
var rsa = new RSAKey(); // rsa engine (object) for signing SSH SHA1 digest
var keyvalidity=0; //key pair is ok?

var timeout;

var proxypath = "";

var tt_sid = "";    // TT_SID produced by me
var ssh_sid = "";   // SSH_SID received by Proxy
var tt_aes_key;     // AES Key to be used with AES-GCM for encrypting Keystrokes and decrypting Server responses

//PKCS#8 Server Public Key string, to be used to verify Digital Signature of Shared Secret sent by Server
var server_public_key = "";

var show_auth = false;

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function hexToBuf(hex){
  var tA = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  return tA//.buffer;
}
function bufToHex(byteArray) {
    return Array.prototype.map.call(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function bufToBase64(buffer){
  let binary = '';
  let bytes = new Uint8Array(buffer);
  let len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function hexToBase64(hex){
  buffer = hexToBuf(hex) // Convert Hex String to BytesArray
  b64 = bufToBase64(ba) // Convert BytesArray to Base64 String
}

function drawPB(size, progress){
  p = Math.round((progress*100)/size)
  $("progressbar2").style.width=p+'%';
  //$("pb_label").innerHTML="shake your mouse... entropy collection="+p+'%';
  $("msg").value="entropy collection = "+p+'%';
}


/*
* UTILITY: debug msg
*/
function msg(m){ //append a debug msg in the box
  var s = $("dbg_txtarea").value;
  if (s) $("dbg_txtarea").value = s + "\n" + "- " + m;
  else $("dbg_txtarea").value = "- " + m;
}
function resetmsg(){ //reset debug msg box
  $("dbg_txtarea").value = "";
}


/*
* RSA KEY PAIR GENERATION
* generates a new RSA key pair (PEM and OPENSSH file format)
*/
function reseed(event, count) {
    var t = [];
    function w(e) {
      var crossBrowserCoordinates = e.mouse().page; // e.mouse().page is an object like this { x: <number>, y: <number>  } where x and y properties that represent the cursor position
      t.push([crossBrowserCoordinates.x, crossBrowserCoordinates.y, +new Date]);//The unary + operator converts a value to a number(date converted to a number gives the number of milliseconds.)
      //alert(crossBrowserCoordinates.x);
      //alert(t.length);
      drawPB(count,t.length);
      if (t.length < count) { return; }
      	drawPB(count,t.length);
        //$("progressbar1").style.visibility="hidden";
        //drawPB(100,0);
        MochiKit.Signal.disconnect(mouse_event);
        Math.seedrandom(t, true);        // Mix in any previous entropy.
	keygeneration();
    }
    var mouse_event = MochiKit.Signal.connect(document, event, w);
}

function entropy_collector(){ // Define a custom entropy collector
  resetmsg();
  keyvalidity = 0;
  $("progressbar1").style.visibility="visible";
  reseed('onmousemove', 6000); // Reseed after 6000 mouse moves (about a minute of user-interface event observations)
}

function keygeneration(){
  var start = new Date();
  //key pair generation --rsa2.js-- with new RNG interface (SeededRandom)
  rsa.generate($('keylenght').value,"10001"); //(e=0x10001)
  //Hex key parameters
  var n = rsa.n.toString(16); //modulus
  var e = rsa.e.toString(16); //public exp e = 0x10001
  var d = rsa.d.toString(16); //private exp
  var p = rsa.p.toString(16); //prime1
  var q = rsa.q.toString(16); //prime2
  var exp1 = rsa.dmp1.toString(16); //dp
  var exp2 = rsa.dmq1.toString(16); //dq
  var coeff = rsa.coeff.toString(16); //qInv
  //set key pair
  rsa.setPrivateEx(n,e,d,p,q,exp1,exp2,coeff);
  rsa.setPublic(n,e);

  msg("key pair generation...ok");
  //check key validity
  checkkeyvalidity();
  msg("TIP: store the private key in a safe place");
  msg("TIP: install the public key on your SSH server");

  //encode private key
  var pem = sk2pemfileformat(n,e,d,p,q,exp1,exp2,coeff); //--rsa2pem.js--
  $("sk_file").value = pem;
  //encode public key
  openssh_pk = pk2opensshfileformat(n,e); //--rsa2pem.js--
  $("pk_file").value = openssh_pk;

  $('usr').focus();//fix spacebar firefox problem
  var end = new Date();
  var secondsElapsed = (end - start) / 1000;
  msg("-- key generated in " + secondsElapsed + " secs --");
}


/*
* RSA KEY PAIR EXTRACTION
* extracts an RSA key pair from a PEM Private Key
*/
function importsk(){
  //extract and set private and public keys
  rsa.setKeyFromPem($("sk_file").value.trim()); //--pem2rsa.js--
  var n = rsa.n.toString(16);
  var e = rsa.e.toString(16);
  //public key file encode
  openssh_pk = pk2opensshfileformat(n,e); //--rsa2pem.js--
  $("pk_file").value = openssh_pk;
  resetmsg();
  msg("key extracting...ok");
  //check key validity
  checkkeyvalidity();
  $('usr').focus();//fix spacebar firefox problem
}


/*
* CHECK KEY PAIR VALIDITY
*/
function checkkeyvalidity(){
  if (rsa.decrypt(rsa.encrypt("test")) == "test"){
    msg("key pair validity...ok");
    keyvalidity = 1;
  }
  else {
    msg("key pair validity...error");
    keyvalidity = 0;
  }
}


/*
* RANDOM SESSION ID [TODO: to improve]
* generates a random SID to identify the terminal session
*/
function randomsid(){
  var s="";
  for (var i=0; i < 255; i++) {
    var r = 0;
	// now get a random number between 0 and 255
	// numbers not in the range are intentionally discarded
	// as it reduces the chance of predicting the seed, by not
	// using all of the numbers generated by the PRNG
	do {
	  r = Math.round(Math.random()*1000);
	} while(r >= 255);
	r = r.toString(16);
	if (r.length == 1) r = "0"+r;
	s += r;
  }
  return s;
}

function getServerPubKeyPkcs8(){
  // Gets the PKCS#1 formatted Server Public Key from the corresponding TextArea in the page
  server_public_key = $("pubkey_textarea").value.trim();
  msg("Server public key read...");
}


/*
* SSH CONNECTION
* if ssh connection succeeds handleServerResult_Connect receives the digest to sign and send by send_digest_sig()
* if authentication succeeds handleServerResult_Auth starts the terminal emulation
*/
function ssh_connect() {

  var kp = $('pk_file').value;  // My Public Key, composed from the inserted Private Key
  var user = $('usr').value;
  var hostname = $('hn').value;
  var port = $('p').value;
  var proxy_ip = $('proxy_ip').value;

  if(kp == "" || server_public_key=="" || user=="" || hostname=="" || port=="" || proxy_ip==""){
    alert("Please fill all the fields!");
  }
  else if(keyvalidity==0){
    alert("Invalid Public/Private key pair!");
  }
  else{

    // Getting Proxy IP from the corresponding text field in the HTML and updating the Proxy Path global var
    proxypath = "https://" + $('proxy_ip').value + "/trustyterm/";

    // Generating the random TrustyTerm Session ID
    tt_sid = randomsid();
    msg("TT_SID generated");

    show_auth = $('check_auth').checked;

  	var qry = queryString({TT_SID:tt_sid, user:user, hostname:hostname, kp:kp, port:port});
    if (show_auth){
      alert("--SSH CONNECTION REQUEST--\n"+"TT_SID = "+tt_sid+"\n"+"USER = "+user+"\n"+"HOST = "+hostname+"\n"+"PORT = "+port+"\n"+"PUBLIC KEY = "+kp+"\n"); //DEBUG
    }

    var d = doXHR(proxypath+'info',
                  { method:'POST',
                    sendContent:qry,
                    headers: {Accept: 'application/json'}
                  }
            );
    d.addCallback(handleServerResult_Connect);
    d.addErrback(handleServerError_Connect);
  
  }
}

function handleServerError_Connect(err){
  alert(err.message + " (ssh connection error)" );
}

function handleServerResult_Connect(res) { //res.responseText contains the Digest to digitally sign
  var m;
  var type_digest;
  var digest;
  var hSig;
  var json;

  if (show_auth) alert("--SSH CONNECTION RESPONSE--\n"+res.responseText); //DEBUG
  //json = evalJSONRequest(res);
  json = JSON.parse(res.responseText); // more secure than evalJSONRequest of Mochikit which uses eval()
  if (json.msg) m = json.msg;
  if(json.type_digest && json.digest){
    type_digest = json.type_digest;
    digest = json.digest; // Digest, computed with SHA1, so 40 hex chars
  }
  if(m=="digest" && digest && type_digest) {
    msg("Digest received");
    hSig = rsa.signDigest(digest, type_digest); // Digital Signature (RSASSA-PKCS1-v1_5 of Digest), 512 hex chars (256 bytes)
    msg("Digital Signature computed")
    //console.log("Digest Signature: " + hSig);

    // Importing Server Public Key for encrypting Digital Signature with RSA-OAEP

    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = server_public_key.substring(pemHeader.length, server_public_key.length - pemFooter.length);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    // Importing Server Public Key for RSA-OAEP Encryption
    window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {name: "RSA-OAEP", hash: "SHA-256"},
        false,
        ["encrypt"],
    )
    .then( function (serv_pubkey) { // serv_pubkey is the CryptoKey to be used for RSA-OAEP encryption
        // Genereting AES Key for encrypting Digital Signature
        aesKey_bytes = window.crypto.getRandomValues(new Uint8Array(32)); // Uint8Array of 256 bit AES Key
        window.crypto.subtle.importKey(
            "raw", aesKey_bytes, "AES-CBC", true, ["encrypt"]
        )
        .then( function (aesCryptoKey) {  // aesCryptoKeys is the CryptoKey to be used for AES-CBC encryption
            // Encrypting Digital Signature with AES Key
            iv = window.crypto.getRandomValues(new Uint8Array(16)); // Uint8Array of 128 bit IV
            window.crypto.subtle.encrypt( {name:"AES-CBC", iv}, aesCryptoKey, hexToBuf(hSig) )
            .then( function (encSig) {
                // Encrypting AES Key with RSA-OAEP
                window.crypto.subtle.encrypt({name: "RSA-OAEP"}, serv_pubkey, aesKey_bytes)
                .then( function (encKey){
                    iv_hex = bufToHex(iv); // Hex of IV
                    encSig_hex = bufToHex(new Uint8Array(encSig)); // Hex of Digital Signature encrypted with AES
                    encKey_hex = bufToHex(new Uint8Array(encKey)); // Hex of Encrypted AES Key
                    msg("Encryption of Digital Signature computed");
                    msg("Sending Encr Sig to Proxy...");
                    send_encr_digest_sig(iv_hex, encSig_hex, encKey_hex);
                })
                .catch(function(err){
                    alert("Failed encryption of AES Key with RSA-OAEP: " + err);
                });
            })
            .catch(function(err){
                alert("Failed encryption of Digital Signature with AES-CBC: " + err);
            });
        })
        .catch(function(err){
            alert("Failed import of AES Key: " + err);
        });
    })
    .catch(function(err){
        alert("Failed import of Server Public Key: " + err);
    });
  }
  else{
      msg("ssh connection error ["+ m + "]");
  }
}

function send_encr_digest_sig(iv_hex,encSig_hex,encKey_hex){
  var qry = queryString({'TT_SID':tt_sid, 'IV':iv_hex, 'EncSig':encSig_hex, 'EncKey':encKey_hex});
  //if (show_auth) alert("--SSH AUTHENTICATION REQUEST--\n"+"SID = " + tt_sid +"\n"+"DIGEST SIGNATURE = " + sig ); //DEBUG

  var d = doXHR(proxypath+'encr_sig', { method:'POST',
                         sendContent:qry,
                         headers: {Accept: 'application/json'}
                       }
               );
  d.addCallback(handleServerResult_Auth);//this callback fires when the XHR returns successful
  d.addErrback(handleServerError_Auth);//this callback fires when the XHR fails
}

function handleServerError_Auth(err){
  alert(err.message + " (sending digest error)" );
}

function handleServerResult_Auth(res) {//res.responseText contains our result.
  var m;
  var json;
  if (show_auth) alert("--SSH AUTHENTICATION RESPONSE--\n"+res.responseText); //DEBUG
  //json = evalJSONRequest(res);
  json = JSON.parse(res.responseText);
  if(json.msg) m = json.msg;
  if(json.ssh_session_id) ssh_sid = json.ssh_session_id;

  if(m == "AUTH_OK") {
    $("btnconnect").disabled="true";
    msg("Server Authentication OK");
    timeout = window.setTimeout(request_session_setup_data, 100);
  }
  else {
    alert("Authentication failed!");
  }
  $('usr').focus();//fix spacebar firefox problem
}

//================= NEW CODE =================
// Polling Proxy to get Shared Secret and Digital Signature
function request_session_setup_data(){
  var qry = queryString({'tt_session_id':tt_sid, 'phase':'3'});
  var d = doXHR(proxypath+'server_session_setup', { method:'POST',
                         sendContent:qry,
                         headers: {Accept: 'application/json'}
                       }
               );
  d.addCallback(handleServerResult_sessionData);
  d.addErrback(handleServerError_sessionData);
}

function handleServerError_sessionData(err){
  alert(err.message + " (cannot correctly handle session setup data from server)" );
}

function handleServerResult_sessionData(res){
  //var json = evalJSONRequest(res);
  var json = JSON.parse(res.responseText);
  if (json.encrypted_data == ""){
    timeout = window.setTimeout(request_session_setup_data, 100);
  }
  else{
    // The response should contain the Encrypted Shared Secret and the Signature

    // Decrypting Shared Secret with my Private Key (RSAES-PKCS1-v1_5 decryption)
    decrypt = new JSEncrypt();
    decrypt.setPrivateKey($('sk_file').value);
    shared_secret_plain = decrypt.decrypt(json.encrypted_data); // JSON string of Plaintext of Shared Secret
    plaintext_json = JSON.parse(shared_secret_plain);  // JSON object, for accessing fields of JSON Shared Secret

    signat_bytes = Uint8Array.from(atob(json.signat), c => c.charCodeAt(0));
    shared_secret_bytes = new TextEncoder("utf-8").encode(shared_secret_plain);

    // Importing Server Public Key

    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = server_public_key.substring(pemHeader.length, server_public_key.length - pemFooter.length);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
          name: "RSA-PSS",
          hash: "SHA-512",
        },
        false,
        ["verify"],
    )
    .then( function (serv_pubkey) {
        // Server Public Key imported, going to verify Signature
        msg("Server Public CryptoKey created");
        window.crypto.subtle.verify(
            {name: "RSA-PSS", saltLength: 32},
            serv_pubkey,
            signat_bytes,
            shared_secret_bytes
        )
        .then( function (result) {
          if(result == true){
            // Digital Signature is valid, I can build CryptoKey of the AES key received
            msg("Digital signature of Shared Secret is valid, AES-GCM key received is good :)");

            // Building CryptoKey object from AES hex key received
            var key_buf = hexToBuf(plaintext_json.tt_aes_key);
            window.crypto.subtle.importKey(
                "raw",
                key_buf,
                {name: "AES-GCM"},
                false,
                ['encrypt','decrypt']
            )
            .then(function(key){
                // CryptoKey of AES key built, I can start the session
                msg("TT_AES CryptoKey created")
                tt_aes_key = key;
                t = trustyterm.Terminal("term"); //--trustyterm.js--, parameter is actually useless now
            })
            .catch(function(err){
                alert("Failed to setup AES key!");
                console.error(err);
            });

          }
          else{
            alert("Digital signature of Shared Secret is not valid :(");
          }
        })
        .catch(function(err){
          alert("Something went wrong in the Digital Signature verification step!");
          console.log(err);
        });

    })
    .catch(function(err){
      alert("Server Public CryptoKey building failed! Insert a valid PKCS#8 Public Key...");
      console.log(err);
    });

  }
}
//============================================

undefined;