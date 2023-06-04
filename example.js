const publicKey = `-----BEGIN PUBLIC KEY-----

.... PLACE YOUR PUBLIC KEY ....

-----END PUBLIC KEY-----`

// Data to encrypt
const plain = '1234567891011121'


// Parsing public key string
var rsaKey = new RSAKey()
rsaKey.readPKCS8PubKeyHex( pemtohex(publicKey))

// Generate random Aes Key and IV
const aesKey = CryptoJS.lib.WordArray.random(32);
const iv = CryptoJS.lib.WordArray.random(16);

// Combine Aes Key & IV
const plainKeysRaw = aesKey.clone().concat(iv);
const plainKeysBytes = wordArrayToByteArray(plainKeysRaw)

// Encrypt our AES Key & IV using RSA
const encryptedKeysHex = rsaKey.encrypt( plainKeysBytes );
const encryptedKeysRaw = sjcl.codec.hex.toBits(encryptedKeysHex)

// Convert CryptoJS data to SJCL
const ivBits = sjcl.codec.hex.toBits(iv.toString());
const aesKeyBits = sjcl.codec.hex.toBits(aesKey.toString());

// Encrypt plain data using AES-GCM
let cipher = new sjcl.cipher.aes(aesKeyBits)
const encryptedData = sjcl.mode.gcm.encrypt(cipher, sjcl.codec.utf8String.toBits(plain), ivBits );

// Combine encrypted AesKey+IV and Encrypted Data (Note: Auth tag is on the last 16 bytes)
const resultRaw = sjcl.bitArray.concat(encryptedKeysRaw, encryptedData)

// Final round, encode it with base64
const resultBase64 = sjcl.codec.base64.fromBits(resultRaw);

console.log(resultBase64);

// Test with your backend
/* 
fetch('http://127.0.0.1:3000/?data=' + encodeURIComponent(resultBase64)).then(res => {
     res.json( console.log )
})
*/