/* NAME: trustyterm.js
 * AUTHOR: Mirko Di Silvio
 *
 * DEPENDS ON :
 * Sarissa library (http://sarissa.sourceforge.net/doc/sarissa)
 * 		sarissa.js
 * 		sarissa_dhtml.js
 * Mochikit
*/

var xterm = new Terminal();  // instantiating xterm object

trustyterm={};

trustyterm.Terminal_ctor=function(id) {

  var buf="";
  var timeout;
  var error_timeout;
  var keybuf=[];
  var key_to_hash=[];
  var sending=0;
  var rmax=10;
  var sk = false;
  var ctrlT = false;
  var ctrlN = false;
  var ctrlW = false;

  function error() {
    msg("Connection lost...");
  }

  /*
  -send keypresses
  -polls the server for updates with an exponentially growing timeout
   when the screen hasn't changed. The timeout is also resetted
   as soon as a key is pressed.
  */
  function update() {
    var d;

    if(sending==0) {
      sending = 1;

    	var send = "";
      //var send_hash = "";
    	while(keybuf.length>0) { // retrieve from keybuf the string to send
    	  send += keybuf.pop();
        //send_hash += key_to_hash.pop();
    	}

      if (send!=""){

        // Sending hash of keystroke, session token and counter is no longer needed since AES-GCM usage
        //send_hash = sha3_512(session_token + current_counter.toString() + send_hash);
        //current_counter += counter_unit_inc;

        // Encrypting keystrokes

        var IV_bytes = new Uint8Array(12);  // 96 random bits for IV
        window.crypto.getRandomValues(IV_bytes);

        var plain_bytes = new TextEncoder().encode(send);    // Uint8Array of plaintext encoded as "utf-8"

        var algo = {name: "AES-GCM", iv: IV_bytes, tagLength: 128}

        window.crypto.subtle.encrypt(algo,tt_aes_key,plain_bytes)
        .then( function (cipher) {  // cipher is the ByteArray containing ciphertext bytes, togheter with TAG
            var cipher_bytes = new Uint8Array(cipher);
            var cipher_hex = bufToHex(cipher_bytes);

            var tosend = bufToHex(IV_bytes) + cipher_hex;    // IV|CIPHER|TAG as hex string

            //POST (so, send keystroke)
            /*var qry = queryString({TT_SID:tt_sid, SSH_SID: ssh_sid, k:tosend});
            d = doXHR(proxypath+'u',
                     { method: 'POST',
                       sendContent:qry,
                       headers: {Accept: 'text/json'}
                     });*/

            d = doSimpleXMLHttpRequest(proxypath+'u', {TT_SID:tt_sid, SSH_SID: ssh_sid, k:tosend});
            d.addCallback(handleServerResult_Update);
            d.addErrback(handleServerError_Update);
            error_timeout=window.setTimeout(error,5000);
        })
        .catch(function(err){
            console.error(err);
        });
        
      }

      else{
        //GET (so, update terminal)
        d = doSimpleXMLHttpRequest(proxypath+'u', {TT_SID:tt_sid, SSH_SID: ssh_sid, k:send});
        d.addCallback(handleServerResult_Update);
        d.addErrback(handleServerError_Update);
        error_timeout=window.setTimeout(error,5000);
      }
    }
  }

  function handleServerError_Update(err){
    msg(err.message + " (update request error)");
  }

  function handleServerResult_Update(res) { //res.responseText contains our result.

    var resp_json = JSON.parse(res.responseText);
    var msg = resp_json.msg;

    if (msg == "Keystrokes authentication failed"){
      alert("Connection closed: Keystrokes authentication failed, proxy server could be compromised.");
      error();
      return;
    }
    

    if (msg == "SSH Session deleted"){
      alert("SSH Session deleted from Proxy and Server!");
      error();
      return;
    }

    if (msg == "Invalid TT_SID"){
      alert("Invalid TT_SID!");
      error();
      return;
    }

    window.clearTimeout(error_timeout);

    if(msg == 'IDEM'){
      rmax*=2;
      if(rmax>1000) rmax=1000;
    }
    else{
      var iv_hex = msg.substr(0, 24);
      var cipher_hex = msg.substr(24); //Includes tag, which are last 32 hex chars

      var iv_buf = hexToBuf(iv_hex);
      var cipher_buf = hexToBuf(cipher_hex);

      var algo = {name: 'AES-GCM', iv: iv_buf, tagLength: 128};
      window.crypto.subtle.decrypt(algo, tt_aes_key, cipher_buf)
      .then(function(decrypted){
          //returns an ArrayBuffer containing the encrypted data
          let decoded = new TextDecoder().decode(decrypted);
          xterm.write(decoded);

      })
      .catch(function(err){
        // If tag or ciphertext are not good, this exception will be thrown!
        alert("WARNING: decryption failed. Proxy may be compromised...");
        console.error(err);
        return;
      });

      rmax=10;
    }

    sending=0;
    timeout=window.setTimeout(update,rmax);
  }

  function queue(s, sa) { //accoda il carattere del tasto premuto in keybuf e setta timeout a 1 ms se sending=0
    keybuf.unshift(s);  // add s to the beginning of keybuf array
    key_to_hash.unshift(sa);  // add sa to the beginning of key_to_hash_array
    if(sending==0) {
     window.clearTimeout(timeout);
     timeout=window.setTimeout(update,1);
    }
  }

  function d2h(d){
      return d.toString(16);
  }

  //================= NEW CODE =================
  function stringToHex(tmp){
      var str = '',
          i = 0,
          tmp_len = tmp.length,
          c;

      for (; i < tmp_len; i += 1){
          c = tmp.charCodeAt(i);
          str += d2h(c);
      }

      if (str.length == 1){
        str = "0"+str;
      }

      return str;
  }
  //============================================

  function sleep(milliseconds) {
    var start = new Date().getTime();
    for (var i = 0; i < 1e7; i++) {
      if ((new Date().getTime() - start) > milliseconds){
        break;
      }
    }
  }



  function specialKey(key){
    // This method handles all special keys that are only registered via onkeydown events (not onkeypress)

    var ESC = String.fromCharCode(27); // ^[
    var ESC_HEX = stringToHex(String.fromCharCode(27)); // 1b
    
    switch(key){
    	case 'Enter':
      	  queue(String.fromCharCode(13), stringToHex(String.fromCharCode(13)));
          carriage_return_flag = 1;
      	  return 1;
      	  break;
    	case 'Tab':
      	  queue(String.fromCharCode(9), stringToHex(String.fromCharCode(9)));
      	  return 1;
      	  break;
    	case 'Backspace': // lo faccio corrispondere al "DEL", quindi al carattere con valore 127
      	  queue(String.fromCharCode(127), stringToHex(String.fromCharCode(127)));
      	  return 1;
      	  break;
      case 'PageUp':
      	  queue(ESC + "[5~", ESC_HEX + "[5~");
      	  return 1;
      	  break;
      case 'PageDown':
      	  queue(ESC + "[6~", ESC_HEX + "[6~");
      	  return 1;
      	  break;
      case 'End':
      	  queue(ESC + "[4~", ESC_HEX + "[4~");
      	  return 1;
      	  break;
      case 'Home':
      	  queue(ESC + "[1~", ESC_HEX + "[1~");
      	  return 1;
      	  break;
      case 'ArrowUp':
      	  queue(ESC + "[A", ESC_HEX + "[A");
      	  return 1;
      	  break;
      case 'ArrowDown':
      	  queue(ESC + "[B", ESC_HEX + "[B");
      	  return 1;
      	  break;
      case 'ArrowRight':
      	  queue(ESC + "[C", ESC_HEX + "[C");
      	  return 1;
      	  break;
      case 'ArrowLeft':
      	  queue(ESC + "[D", ESC_HEX + "[D");
      	  return 1;
      	  break;
      case 'Insert':
      	  queue(ESC + "[2~", ESC_HEX + "[2~");
      	  return 1;
      	  break;
      case 'Delete':
      	  queue(ESC + "[3~", ESC_HEX + "[3~");
      	  return 1;
      	  break;
      case 'F1':
      	  queue(ESC + "[[A", ESC_HEX + "[[A");
      	  return 1;
      	  break;
      case 'F2':
      	  queue(ESC + "[[B", ESC_HEX + "[[B");
      	  return 1;
      	  break;
      case 'F3':
      	  queue(ESC + "[[C", ESC_HEX + "[[C");
      	  return 1;
      	  break;
      case 'F4':
      	  queue(ESC + "[[D", ESC_HEX + "[[D");
      	  return 1;
      	  break;
      case 'F5':
      	  queue(ESC + "[[E", ESC_HEX + "[[E");
      	  return 1;
      	  break;
      case 'F6':
      	  queue(ESC + "[17~", ESC_HEX + "[17~");
      	  return 1;
      	  break;
      case 'F7':
      	  queue(ESC + "[18~", ESC_HEX + "[18~");
      	  return 1;
      	  break;
      case 'F8':
      	  queue(ESC + "[19~", ESC_HEX + "[19~");
      	  return 1;
      	  break;
      case 'F9':
      	  queue(ESC + "[20~", ESC_HEX + "[20~");
      	  return 1;
      	  break;
      case 'F10':
      	  queue(ESC + "[21~", ESC_HEX + "[21~");
      	  return 1;
      	  break;
      case 'F11':
      	  queue(ESC + "[23~", ESC_HEX + "[23~");
      	  return 1;
      	  break;
      case 'F12':
      	  queue(ESC + "[24~", ESC_HEX + "[24~");
      	  return 1;
      	  break;
    	default:
          return 0;
    }
  }

  function keyCombo(key) {
    var keyCode = key.charCodeAt();
    //console.log('[In keyCombo]: character code is ' + keyCode)
    // This method translates ctrl/alt/meta key combos such as ctrl-c into their string equivalents.
    if (keyCode >= 97 && keyCode <= 122) queue(String.fromCharCode(keyCode - 96), ('00' + Number(keyCode-96).toString(16)).slice(-2)); // Ctrl-[a-z]
    else if (keyCode >= 65 && keyCode <= 90) queue(String.fromCharCode(keyCode - 64), ('00' + Number(keyCode-64).toString(16)).slice(-2)); // Ctrl-Shift-[a-z]
    else if (keyCode == 92) queue(String.fromCharCode(28), stringToHex(String.fromCharCode(28))); // Ctrl-\
    else if (key == "^") queue(String.fromCharCode(30), stringToHex(String.fromCharCode(30)));
    else if (key == "_") queue(String.fromCharCode(31), stringToHex(String.fromCharCode(31)));
    else if (key == "[") queue(String.fromCharCode(27), stringToHex(String.fromCharCode(27)));
    else if (key == "]") queue(String.fromCharCode(29), stringToHex(String.fromCharCode(29)));
    else if (key == "@") queue(String.fromCharCode(0), stringToHex(String.fromCharCode(0)));
    else queue(key, key);
  }

  function keydown(e){
    var key = e.key;

    // Handle Ctrl+Shift+V to simulate paste from Clipboard
    if(e.ctrlKey && e.shiftKey && e.key=='V'){
      navigator.clipboard.readText()
      .then( function(clipText) {
        if(clipText!=""){
          len = clipText.length;
          if(len>512){
            clipText = clipText.slice(0,512);
            alert("Clipboard content too long, going to paste first 512 characters only");
          }
          for(i=0; i<512; i++){
            if(clipText.charAt(i).charCodeAt(0)==9) queue(String.fromCharCode(9), stringToHex(String.fromCharCode(9)));
            else if(clipText.charAt(i).charCodeAt(0)==10) queue(String.fromCharCode(10), stringToHex(String.fromCharCode(10)));
            else queue(clipText.charAt(i),clipText.charAt(i));
          }
        }
      })
      .catch( function(err) {
        console.log("Error trying to paste from Clipboard");
      });
    }

    //SPECIAL KEY
    var m = specialKey(key); //check if it is a special key
    if (!m) {
      if (!e.ctrlKey && !e.altkey && !e.metaKey) { //Only send a key if no modifiers are held (other than shift)
        // Il tasto premuto è o Shift o un carattere normale
        if(key!='Escape' && key != 'OS' && key!='Shift' && key!='CapsLock' && key!='AltGraph' && key!='Alt')
          queue(key, key);
      }
      else{
        // Un tasto di controllo è mantenuto premuto
        if(key != 'Control' && key != 'Alt' && key != 'Meta' && key!='Shift')
          // È stato premuto un tasto normale mentre un tasto di controllo è mantenuto -> KEYCOMBO!
          keyCombo(key);
      }
    }
    e.cancelBubble = true;
    e.returnValue = false;
    if (e.stopPropagation) {
      e.stopPropagation();
      e.preventDefault();
    }
  }

  function init() {

    $("PrK1_txtarea").value = "";
    $("PuK_txtarea").value = "";
    $("PrK8_txtarea").value = "";
    $("srvrKey_txtarea").value = "";

    // Terminal Appearence
    xterm.open(document.getElementById('xterm'));

    // Setting inner xterm size and xterm buffer size
    xterm._core.resize(170,24);

    // Telling SSHD the terminal output size
    queue("stty rows 24 cols 170");
    queue(String.fromCharCode(13), stringToHex(String.fromCharCode(13)));
    carriage_return_flag = 1;
    update();

    /*xterm.on('key', (key, ev) => {
      keydown(ev);
    });*/
    xterm.attachCustomKeyEventHandler(e => {
      keydown(e);
    });

    timeout=window.setTimeout(update, 10); // calls update every 10 ms

    // If the tab or browser closes, we send the "exit" command to SSHD
    /*window.addEventListener('beforeunload', function (e) {
      e.preventDefault();
      alert("Tab is being closed");
      queue("exit");
      queue(String.fromCharCode(13), stringToHex(String.fromCharCode(13)));
      carriage_return_flag = 1;
      update();
    });*/
  }


  init();

}

trustyterm.Terminal=function(id) {
	return new this.Terminal_ctor(id);
}

undefined;