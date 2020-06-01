/*! NAME: rsadigestsign.js 
* AUTHOR: Di Silvio Mirko 
*
*
* dipenda da:
*   Tom Wu's rsa2.js  
*/  




var HASHID = [];
HASHID['sha1'] = "3021300906052b0e03021a05000414";
HASHID['md5'] = "3020300c06082a864886f70d020505000410";


function codificaEMSA(d, keySize, hashAlg) { //ritorna la codifica EMSA-PKCS1-v1_5 -> EM = 0x00|0x01|PS|0x00|T dove PS sono k-Tlen-3 0xFF e T = hashID|H
  var k = keySize / 4; //lunghezza in byte del modulo RSA n
  var T = HASHID[hashAlg] + d; //T = hashID|H
  var PS = "";
  var PSlen = k - T.length - 6;//6(3 byte ossia 6 cifre decimali) per togliere "00" e "0100" così EM ha lunghezza k
  for (var i = 0; i < PSlen; i +=2) {
    PS += "ff";
  }
  var EM = "0001" + PS + "00" + T; 
  return EM;
}

function zeroPad(h, k) {
  var pad = "";
  var padlen = k / 4 - h.length;
  for (var i = 0; i < padlen; i++) {
    pad = pad + "0";
  }
  return pad + h;
}


/**
 * sign for digest with RSA private key
 * member of RSAKey
 * string d: digest to be signed
 * string hashAlg: hash algorithm name for signing
 * returns hexadecimal string of signature value
 */

function _signDigest(d, hashAlg) {
  var EM = codificaEMSA(d, this.n.bitLength(), hashAlg);
  var m = parseBigInt(EM, 16);//converte EM in un intero non negativo
  var s = this.doPrivate(m);//applica la primitiva di firma usando la chiave privata
  var S = s.toString(16);//firma in esadecimale
  var signature=zeroPad(S, this.n.bitLength());//padding affinchè la lunghezza sia k
  return signature;
}


RSAKey.prototype.signDigest = _signDigest; // aggiungiamo la funzione alla classe RSAkey

undefined;