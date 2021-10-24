// DOM Elements.
const shcInput = document.getElementById("shc");
const submitButton = document.getElementById("submit");
const outputEl = document.getElementById("output");
const debugShcEl = document.getElementById("debug_shc");
const debugJwtEl = document.getElementById("debug_jwt");
const debugJwtHeaderEl = document.getElementById("debug_jwt_header");
const debugJwtPayloadEncodedEl = document.getElementById("debug_jwt_payload_encoded");
const debugJwtPayloadDecodedEl = document.getElementById("debug_jwt_payload_decoded");


// Converts SHC string of the form shc:/#### into a JWT string.
function convertShcUriToJwt(shcStr) {
  // Remote shc:/ prefix.
  shcStr = shcStr.substr(5, shcStr.length-5);
  // Takes each set of digits and adds 45 to turn it into a char.
  const tokens = [];
  for (let i = 0; i < shcStr.length; i+=2) {
    let charCode = parseInt(shcStr.substr(i,2), 10) + 45;
    tokens.push(String.fromCharCode(charCode));
  }
  return tokens.join("");
}


/**
 * Decodes a base64 string into a Uint8Array.
 *
 * Most common b64 decode implementations assume that the encoded payload is ASCII characters.
 * However, in this case the payload is zlib-deflated UTF8 characters. Standard atob() will not
 * work. I wrote the below code based on several reference implementations and guides:
 * - https://www.base64decode.org/
 * - https://en.wikipedia.org/wiki/Base64
 * - https://github.com/auth0/jwt-decode/blob/222db61fbaeea8ffd412a306039fea769ce43093/build/jwt-decode.js
 * - https://github.com/danguer/blog-examples/blob/master/js/base64-binary.js
 * - https://github.com/python/cpython/blob/03e9f5dc751b8c441a85f428abc3f432ffe46345/Modules/binascii.c#L372-L515
 * - https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
 */
function b64Decode(encodedStr) {
  // The valid 64 chars specified for b64
  // https://www.base64decode.org/
  const validB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  // Remove trailing "=" which are sometimes used to ensure the payload has multiples of 4 b64
  // chars.
  encodedStr = encodedStr.replace(/=+$/, "");
  // RFC 4648 allows "-" and "_" to be used instead of "+" and "/" respectively so convert those.
  encodedStr = encodedStr.replace(/\-/g, "+");
  encodedStr = encodedStr.replace(/\_/g, "/");
  // Check to see if any invalid characters.
  const invalidRemoved = encodedStr.replace(/[^A-Za-z0-9\+\/]/g, "");
  if (invalidRemoved.length !== encodedStr.length) {
    throw new Error("Invalid input: b64 encoded values should only contain A-Z a-z 0-9 + / - _ =");
  }
  // 4 b64 encoded chars map to at most 3 decoded bytes. Extra padding is added during
  // encoding so trim the expected decoded size via floor.
  const decodedNumBytes = Math.floor(encodedStr.length / 4 * 3);
  const outputArray = new Uint8Array(decodedNumBytes);
  let inputIndex = 0;
  for (let outputIndex = 0; outputIndex < decodedNumBytes; outputIndex += 3) {
    // Get the 6-bit encoding for each input b64 char. If inputIndex exceeds length charAt returns
    // "" which receives an indexOf 0 and will create a x_6bit value of 0b00000000.
    const a_6bits = validB64Chars.indexOf(encodedStr.charAt(inputIndex++));
    const b_6bits = validB64Chars.indexOf(encodedStr.charAt(inputIndex++));
    const c_6bits = validB64Chars.indexOf(encodedStr.charAt(inputIndex++));
    const d_6bits = validB64Chars.indexOf(encodedStr.charAt(inputIndex++));
    // Turn the 4 6bit chunks into 3 8bit chunks
    // Input:   010011 010110 000101 101110
    // Outputs: 01001101  01100001 01101110
    const a_8bits = (a_6bits << 2) | (b_6bits >> 4);
    const b_8bits = ((b_6bits & 0b001111) << 4) | (c_6bits >> 2);
    const c_8bits = ((c_6bits & 0b000011) << 6) | d_6bits;
    // In some cases the resulting 8bit chunks can be empty. Keep non-empty.
    // Example:
    // Decoded: 01001101  00000000 00000000
    // Encoded: 010011 010000 000000 000000
    // We can throw out the 2 trailing decoded values.
    outputArray[outputIndex] = a_8bits;
    if (b_8bits != 0) outputArray[outputIndex+1] = b_8bits;
    if (c_8bits != 0) outputArray[outputIndex+2] = c_8bits;
  }
  return outputArray;
}


/**
 * Converts a UTF-8 Uint8Array to a string.
 *
 * Shamelessly stolen from:
 * - https://developer.mozilla.org/en-US/docs/Glossary/Base64
 */
function utf8ArrayToStr(aBytes) {
  let sView = "";
  for (var nPart, nLen = aBytes.length, nIdx = 0; nIdx < nLen; nIdx++) {
    nPart = aBytes[nIdx];
    sView += String.fromCharCode(
      nPart > 251 && nPart < 254 && nIdx + 5 < nLen ? /* six bytes */
        /* (nPart - 252 << 30) may be not so safe in ECMAScript! So...: */
        (nPart - 252) * 1073741824 + (aBytes[++nIdx] - 128 << 24) + (aBytes[++nIdx] - 128 << 18) + (aBytes[++nIdx] - 128 << 12) + (aBytes[++nIdx] - 128 << 6) + aBytes[++nIdx] - 128
      : nPart > 247 && nPart < 252 && nIdx + 4 < nLen ? /* five bytes */
        (nPart - 248 << 24) + (aBytes[++nIdx] - 128 << 18) + (aBytes[++nIdx] - 128 << 12) + (aBytes[++nIdx] - 128 << 6) + aBytes[++nIdx] - 128
      : nPart > 239 && nPart < 248 && nIdx + 3 < nLen ? /* four bytes */
        (nPart - 240 << 18) + (aBytes[++nIdx] - 128 << 12) + (aBytes[++nIdx] - 128 << 6) + aBytes[++nIdx] - 128
      : nPart > 223 && nPart < 240 && nIdx + 2 < nLen ? /* three bytes */
        (nPart - 224 << 12) + (aBytes[++nIdx] - 128 << 6) + aBytes[++nIdx] - 128
      : nPart > 191 && nPart < 224 && nIdx + 1 < nLen ? /* two bytes */
        (nPart - 192 << 6) + aBytes[++nIdx] - 128
      : /* nPart < 127 ? */ /* one byte */
        nPart
    );
  }
  return sView;
}

function resetDebugData() {
  outputEl.innerHTML = "";
  debugShcEl.innerHTML = "";
  debugJwtEl.innerHTML = "";
  debugJwtHeaderEl.innerHTML = "";
  debugJwtPayloadEncodedEl.innerHTML = "";
  debugJwtPayloadDecodedEl.innerHTML = "";
}


function tryDecode() {
  resetDebugData();
  const shcVal = shcInput.value;
  if (shcVal.length < 5 || shcVal.substr(0,5) != "shc:/") {
    outputEl.innerHTML = `error: must start with shc:/`;
    return;
  }
  debugShcEl.innerHTML = shcVal;

  try {
    const jwt = convertShcUriToJwt(shcVal);
    debugJwtEl.innerHTML = jwt;

    const header = JSON.parse(utf8ArrayToStr(b64Decode(jwt.split(".")[0])));
    const prettyHeader = JSON.stringify(header, undefined, 4);
    debugJwtHeaderEl.innerHTML = prettyHeader;

    const encodedPayload = jwt.split(".")[1];
    debugJwtPayloadEncodedEl.innerHTML = encodedPayload;

    const decodedPayload = b64Decode(encodedPayload);
    debugJwtPayloadDecodedEl.innerHTML = decodedPayload.toString();
    let payload;
    if (header["zip"] === "DEF") {
      payload = JSON.parse(utf8ArrayToStr(pako.inflateRaw(decodedPayload)));
    } else {
      payload = JSON.parse(decodedPayload);
    }
    const prettyPayload = JSON.stringify(payload, undefined, 4);
    outputEl.innerHTML = prettyPayload;
  } catch (e) {
    outputEl.innerHTML = `error check intermediary data: ${e.toString()}`;
  }
}

function registerEventListeners() {
  shcInput.addEventListener("change", tryDecode);
  shcInput.addEventListener("keyup",  tryDecode);
  submitButton.addEventListener("click", tryDecode);
}


registerEventListeners();
