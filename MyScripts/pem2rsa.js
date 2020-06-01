/*! NAME: pem2rsa.js 
* AUTHOR: Mirko Di Silvio
*
* RSAKey class extension to read PKCS#1 RSA private key PEM file 
* 
*/


var index = 0;


function h2d(hex){ // HEX -> DEC
  return parseInt(hex,16);	
}

function nextNbyte(str,n){ // ritorna i prossimi n byte della stringa
  //alert("index = "+ index + " n=" + n);
  var s = str.substr(index,n*2);
  //alert("extract = "+ s);
  index += n*2;
  return s;
}

function nextBlockLength(s){
	
	var b = nextNbyte(s,1);
	var d = h2d(b);
	var l = 0;
	//alert("first byte length = "+ d);
	if(d < 128){
	 	l = d;		
	}else{
		var x = nextNbyte(s,d-128);
		l = h2d(x);
	}
	return l;
}


function getKeyParam(kDER){// keyDER -> k=[n, e, d, p, q, dp, dq, coeff]
	
	var k = new Array(); //array contenente i parametri della chiave privata
	var seq_length = 0;
	index = 0;
	//block
	var tag = '';
	var length = 0;
	var value = '';

	
	//verifico se il primo byte indica un TAG SEQUENCE
	tag = nextNbyte(kDER,1);
	if(tag!='30'){
		alert("error extracting key: NO TAG SEQUENCE.");
		return;
	}
	//alert("TAG SEQUENCE OK");	
		
		
	//calcolo lunghezza sequenza (numero di byte)
	seq_length = nextBlockLength(kDER);
	//alert("SEQUENCE LENGTH = "+seq_length);	
	//alert(kDER.substr(index).length);
	//verifico validita' della lunghezza della sequenza
	if((kDER.substr(index).length/2)!=seq_length){
		alert("error extracting key: WRONG SEQUENCE LENGTH.");
		return;
	}
	//alert("SEQUENCE LENGTH OK");
	
	
	//zero byte
	if (nextNbyte(kDER,3)!='020100'){
		alert("error extracting key: NO ZERO BYTE.");
		return;
	}
	//alert("ZERO BYTE OK");
	
	
	var i = 0;
	for(i = 0;i < 8 ; i++){ //estraggo finalmente i parametri	   
	   tag = nextNbyte(kDER,1);
	   if(tag!='02'){
			alert("error extracting key: NO TAG INTEGER."); //deve essere una sequenza di INTEGER
	        return;
 	  }
 	  //alert("TAG INTEGER OK");
 	  
 	  length = nextBlockLength(kDER);
	  if ((kDER.substr(index).length/2)<length){ // controllo la validita' della lunghezza degli INTEGER
	  	 alert("error extracting key: WRONG INTEGER LENGTH.");
	     return;
	  }
	  
	  value=nextNbyte(kDER,length)
	  //alert((i+1)+"° INTEGER = " + value);
	  
	  k[i] = value;
	  
	}
	
	//alert("EXTRACTION OK...");
	
	return k;
	
}




/**
 * Decodifica un file PEM per settare le chiavi rsa nell'oggetto di classe RSAkey
 * input : PEM private key file
 * 
*/
function _setKeyFromPem(kPEM) {
  //alert("PEM -> RSA ...");
  
  //pemTobase64
  var kB64 = kPEM.replace("-----BEGIN RSA PRIVATE KEY-----", ""); //remove header
  kB64 = kB64.replace("-----END RSA PRIVATE KEY-----", ""); //remove footer
  kB64 = kB64.replace(/[ \n]+/g, ""); //remove all spaces or new lines
  
  //base64ToHex  
  var kHex = b64tohex(kB64); // depends on base64.js
  
  //read key parameters: n, e, d, p, q, dp, dq, coeff from HEX DER data
  var rsakey = getKeyParam(kHex);

  //set private key: n, e, d, p, q, dp, dq, coeff
  this.setPrivateEx(rsakey[0],rsakey[1],rsakey[2],rsakey[3],rsakey[4],rsakey[5],rsakey[6],rsakey[7]);
  
  //set public key: n, e
  this.setPublic(rsakey[0],rsakey[1]);
  
}



RSAKey.prototype.setKeyFromPem = _setKeyFromPem;

undefined;