// fix: libs/jsbn.js
if(!this['navigator']){
    this['navigator'] = {};
}

function wordToByteArray(word, length) {
    var ba = [],
        i,
        xFF = 0xFF;
    if (length > 0)
        ba.push(word >>> 24);
    if (length > 1)
        ba.push((word >>> 16) & xFF);
    if (length > 2)
        ba.push((word >>> 8) & xFF);
    if (length > 3)
        ba.push(word & xFF);

    return ba;
}

function wordArrayToByteArray(p) {
    length = p.sigBytes;
    wordArray = p.words;

    var result = [],
        bytes,
        i = 0;
    while (length > 0) {
        bytes = wordToByteArray(wordArray[i], Math.min(4, length));
        length -= bytes.length;
        result.push(bytes);
        i++;
    }
    return [].concat.apply([], result);
}