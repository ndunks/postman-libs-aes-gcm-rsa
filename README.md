# Postman AES+GCM and RSA Encryption Library


- [JSRSASIGN](https://github.com/kjur/jsrsasign)
- [SJCL](https://github.com/bitwiseshiftleft/sjcl)

## JSRASIGN Note

patched function `pkcs1pad2` to support binary (byte array)


## SJCL Note

*Build command* with minimum dependencies

```

SOURCES="core/sjcl.js core/aes.js core/bitArray.js core/codecString.js core/codecHex.js  core/codecBase64.js core/gcm.js"
cat $SOURCES > sjcl.js

```


## Postman Pre-Reuqest Script Example

This example will encrypt specified header key

``` js

if (!pm.variables.has('PUBLIC_KEY')) {
    throw new Error('Please set PUBLIC_KEY environment')
}

// target header key to encrypt before sending request
const headerToEncrypt =  'x-param-nik'

async function encryptHeader() {
    
    console.log('encrypting header with key:', headerToEncrypt)

    if (!pm.globals.has('cryptolibs')) {
        // installing required code if not exists
        await new Promise((r, j) => pm.sendRequest("https://raw.githubusercontent.com/ndunks/postman-libs-aes-gcm-rsa/main/libs.js", (err, res) => {
            if (err) return j(err)
            code = res.stream.toString('utf8')
            pm.globals.set('cryptolibs', code)
            r(true)
        })
        )
    }
    // Load required libs
    var CryptoJS = require("crypto-js");
    eval(pm.globals.get('cryptolibs'))
        
    // Data to encrypt
    const plain = pm.request.headers.get(headerToEncrypt)

    // Parsing public key string
    var rsaKey = new RSAKey()
    rsaKey.readPKCS8PubKeyHex( pemtohex(pm.variables.get('PUBLIC_KEY')))

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

    // replace plain data in header with encypted
    pm.request.headers.upsert({ key: headerToEncrypt, value: resultBase64 })
}

encryptHeader()

```
