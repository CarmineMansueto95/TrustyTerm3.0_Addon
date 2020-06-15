/*! NAME: rsa2pem.js 
* AUTHOR: Mirko Di Silvio
*
* dipende da: 
*   Tom Wu's base64.js 
*/

function h2d(hex){ //(converte un hex in dec)
  return parseInt(hex,16);	
}

function d2h(dec){ //(converte un dec in hex)	
  var h = dec.toString(16);	
  if( (h.length % 2 ) == 0) { //se la lunghezza è pari
    return h;
  }
  else{ //altrimenti metto uno 0 davanti
   return "0"+h;	
  } 	
}


function splitline(s,n) { //(splitta una stringa s in righe di lunghezza n)
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}


function lengthblock(hex){ // (codifica DER della lunghezza di un blocco di dati hex)	
	var numbyte = hex.length/2;	
	if (numbyte < 128){
		return d2h(numbyte);//basta 1 byte(riesco con 7 bit a codificarla)
	}
	else if(numbyte<=255){
		return "81"+d2h(numbyte);//servono 2 byte
	}else{
		return "82"+d2h(numbyte);//servono 3 byte
	}
}

function h2der(hex){ // (codifica DER di un hex rappresentante un integer)    
   var tag="02";//tag integer   
   if ( h2d( (hex.substring(0,1) ) )>=8) hex="00"+hex; //se il primo byte ha il MSbit a 1 è necessario un leading zero byte
   return tag+lengthblock(hex)+hex; //codifica DER dell'integer
}

function codifica_der(n,e,d,p,q,dp,dq,qInv){ // (codifica DER della sequenza di parametri della chiave privata)	
	var tag ="30"; // sequence	
	var zero = "020100"; // integer 0 -> version header
	// codifica DER dei parametri
	var mod = h2der(n);	
	var pub_exp = h2der(e);
	var pri_exp = h2der(d);
	var prime1 = h2der(p);
	var prime2 = h2der(q);
	var exp1 = h2der(dp);
	var exp2 = h2der(dq);
	var coeff = h2der(qInv);
	
	var blocco = zero + mod + pub_exp + pri_exp + prime1 + prime2 + exp1 + exp2 + coeff;
	var codificablocco = tag + lengthblock(blocco) + blocco //codifica DER della sequenza di parametri

	return codificablocco;
}


/**
 * Codifica una chiave privata RSA nel formato file PEM
 * input : n,e,d,p,q,dp,dq,qInv (parametri della ks)
 * output : codifica PEM 
 * 
*/
function sk2pemfileformat(n,e,d,p,q,dp,dq,qInv){ 
	
	var header= "-----BEGIN RSA PRIVATE KEY-----\n";
	var footer= "\n-----END RSA PRIVATE KEY-----";
	
	// se necessario metto uno 0 davanti in modo da avere gruppi di byte
	if (n.length % 2 !=0 ) n="0"+n;
	if (e.length % 2 !=0 ) e="0"+e;
	if (d.length % 2 !=0 ) d="0"+d;
	if (p.length % 2 !=0 ) p="0"+p;
	if (q.length % 2 !=0 ) q="0"+q;
	if (dp.length % 2 !=0 ) dp="0"+dp;
	if (dq.length % 2 !=0 ) dq="0"+dq;
	if (qInv.length % 2 !=0 ) qInv="0"+qInv;
	
	var der = codifica_der(n,e,d,p,q,dp,dq,qInv); //codifica der ASN.1
	
	var b64 = hex2b64(der); //codifica Base64 dei dati der
	
	return header+splitline(b64,64)+footer; //codifica pem della chiave privata
}


/**
 * Codifica una chiave pubblica RSA nel formato file openSSH (id_rsa.pub)
 * input : n,e (parametri della kp) user,hostname 
 * output : codifica chiave pubblica openSSH 
 * 
*/
function word4bytes(l){ //codifica la lunghezza in una word a 4 bytes
	var hl = d2h(l); //lunghezza in hex
	var res=hl;
	for(i=hl.length;i<8;i++){ //pad 
		res="0"+res;
	}
	return res;
}

function pk2opensshfileformat(n,e){
	//alert(n);
	//alert(e);
	
	// se necessario metto uno 0 davanti in modo da avere gruppi di byte
	//alert(n.length);
	if (n.length % 2 !=0 ) n="0"+n;
	if (e.length % 2 !=0 ) e="0"+e;
	//(bug codifica diversa della kp rispetto a key-gen) mette 00 davanti cosi la length e' 81 e non 80
	if ((n.length/2) % 2 == 0 ) 
	{
		n="00"+n;
		//alert("00 aggiunti");
	}
	
	//codifica: datalength|data
    var s = "000000077373682D727361"; //"ssh-rsa"
    var pub_exp = word4bytes(e.length/2) + e; //e
    var mod = word4bytes(n.length/2) + n; //n
    var stringa_kp = hex2b64(s+pub_exp+mod);
    var codifica_kp = "ssh-rsa " + stringa_kp;
    return codifica_kp;
	
}