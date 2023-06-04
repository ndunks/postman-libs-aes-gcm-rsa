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