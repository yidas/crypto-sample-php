<?php

ini_set("display_errors", 1);
error_reporting(E_ALL);

require __DIR__ . '/../vendor/autoload.php';
// uses phpseclib version 3
use phpseclib3\Crypt\PublicKeyLoader;

/**
 * Simple Encryption
 */

// Setting
$privateKey = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEjGBFFCfVHTwk
wQFvkWrPsrMjpXyuXBhDOdYd6M5a8q6Faymsy4EXAyhMhJUW6C+543vet0DKQFQV
2WYsGALo+uQVhy20PvWTOHpJZd8kRyvSWrDTlePbW80FWJ7gPbfjqeWwfeGrECUo
kshV0SUSMSubkBUgWnsLiF+SxexYeCj8TY1oaYxg3jdJsmk/MeZOXsS/A9M8dWdF
D7uPIcJKXC/RzVJD90PV41b6liiYILdXgNh9iVKYu/hl7HoMREBgRr6wLiQdgU9o
tYJhhG17xFMIaoEuaNxFiydp1mlvmkTQ4gVks5Imn6igEgnJzdyHH3gUZjwMtJr+
ZAGhl93zAgMBAAECggEAbyErwYMe7nmEKwfRxwJCkULp1MrZz0AVG9WUwf6CxpuW
n6syuheqWpeXboQ8Q+JuMb10qT2V7YUnxd7QzTeaVZ6d3ao75kD+2wnA4sUtwLZZ
CavrdQa3+axTJKWx1voughPq4bqbIPyU9fbgPN1vB3UzwdZai5t9HM0ztKoh8vam
pSnoCg1cwNNEzjgDWyCWVIwHjsL143ghimKejtZ4Ocsnnxy9yOjstdMrLVePEHsn
OeVziXh30OeHJxDZJOavOo9RHUFJLWutiz1O3kbpOD4XXpt5ZBv0sqisWRfpE98s
0hwCYiNZ22ctct5mD8ijNSBTKDAbbe1bmZzlChzxGQKBgQD5fcLK9EeZbCqYes9o
MBiOrn6SUV8+3EfnwNPtoT9ywE8LmrdC3f02WPf6f+9Lr7psK3zg8aPfdlz6+EBc
c4PXOz/jM66PS2J/X7DC5H7czIWRIzsp+NKA/QpK9ffIdzfQTkKQDe/STEMe44h+
mevV3qQHjBizwKE/BMrR6/GEfwKBgQDJrQiOyoI48G6T7jnCTMJTHoB9oWDQqFho
XLG+CwgLmQiXu5y+tvK5qP9Vig9W8SFv6WsYpzvY6rSoJNkm0kuAbNMZmt2zp/b8
CXf4Puvh3fWTpp1HK5oYcdeXn5Qxnj7l/yVC/NfvwJlQf3yR2kXj/f5nproK1DZH
Yy4K4uwcjQKBgQDJDHsIqcl47R12OqEgyIFBmYQNzNz//utC6rTdbW9/vVD1fPvp
OpJuVUuf5bCkQTvtJy4+5vqzfOJ4q8zRs5SuwOQ+5sroVktNcYMzyoYgz/9icg2f
SQ/5OfAtcAD43nlvt2EUTObRhPshzSGVQ9w0QHHWUyMk1zoZWndGque5aQKBgEOG
WwIsTdOwtOV08wPaXYolAVKPEPJsG0W+G4kM+oGfmJ/tIjs82CJPskY6to4eqFpn
JgOYItKrKxfNVqPH752tUjUVhDud9nVG2lNVBfeXMJ1iQPDOaYbbvxq2RJEkcdzi
Q+Cc9dQBgZPRS60uDw6aQW8FBO+RRCc8zvK4LeQVAoGAIU32kQGdG6l1fCI+kNpI
oYrIXVEEOJskQNu8YIqiBpALoaRQpI/UGMcksXS1zG3yw8UWQGJUDlelwxRkSNR5
bx2E9akmKUosOyrczkj5yLPYaP4d6OCd0WEgHQFyGUornOt4ZJwNVs3eAVBun9o9
sLdrbFRfhR5aKdg063v7+b8=
-----END PRIVATE KEY-----";

$publicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxIxgRRQn1R08JMEBb5Fq
z7KzI6V8rlwYQznWHejOWvKuhWsprMuBFwMoTISVFugvueN73rdAykBUFdlmLBgC
6PrkFYcttD71kzh6SWXfJEcr0lqw05Xj21vNBVie4D2346nlsH3hqxAlKJLIVdEl
EjErm5AVIFp7C4hfksXsWHgo/E2NaGmMYN43SbJpPzHmTl7EvwPTPHVnRQ+7jyHC
Slwv0c1SQ/dD1eNW+pYomCC3V4DYfYlSmLv4Zex6DERAYEa+sC4kHYFPaLWCYYRt
e8RTCGqBLmjcRYsnadZpb5pE0OIFZLOSJp+ooBIJyc3chx94FGY8DLSa/mQBoZfd
8wIDAQAB
-----END PUBLIC KEY-----";

/**
 * Decrpyt from JS cipher & IV
 */
if ($_POST) {

    // Data fetching
    $jsCipherText = isset($_POST['js_ciphertext']) ? $_POST['js_ciphertext'] : '';
    // var_dump($jsCipherText);exit;
    
    // Decoding
    $chiperRawFromJs = base64_decode($jsCipherText);

    // Decryption - native function
    // if (!openssl_private_decrypt($chiperRawFromJs, $decryptedForJS, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
    //     // die("<script>alert('Error on decription by private key \\n{$error}');history.back();</script>");
    // }

    // Decryption - phpseclib3
    $rsa = PublicKeyLoader::load($privateKey)
        // ->withHash('sha1')
        ->withMGFHash('sha1')
        ;
    $decryptedForJS = $rsa->decrypt($chiperRawFromJs);
}

// Encryption
$plaintext = "Plaintext中文";

// if (openssl_public_encrypt($plaintext, $cipthertext, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
//     $cipthertextB64 = base64_encode($cipthertext);
// } else {
//     $error = openssl_error_string();
//     die("<script>alert('Error on encription by public key \\n{$error}');history.back();</script>");
// }

// // Decryption
// if (!openssl_private_decrypt($cipthertext, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
//     die("<script>alert('Error on decription by private key \\n{$error}');history.back();</script>");
// }

// phpseclib3 method
$rsa = PublicKeyLoader::load($publicKey)
        // ->withHash('sha1')
        ->withMGFHash('sha1')
        ;
$cipthertext = $rsa->encrypt($plaintext);
// var_dump($cipthertext);exit;
$cipthertextB64 = base64_encode($cipthertext);

$rsa = PublicKeyLoader::load($privateKey)
        // ->withHash('sha1')
        ->withMGFHash('sha1')
        ;
$decrypted = $rsa->decrypt($cipthertext);
// var_dump($decrypted);exit;

?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>PHP Encryption</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Padding Libraries -->
    <!-- <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-zeropadding-min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-nopadding-min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-ansix923-min.js"></script> -->
    <!-- <script src="https://cdn.jsdelivr.net/npm/jwk-to-pem@2.0.5/src/jwk-to-pem.min.js"></script> -->
    <script src="https://unpkg.com/node-forge@1.0.0/dist/forge.min.js"></script>
</head>
</head>
<body>
    
    <p>Private Key</p>
    <textarea name="" id="js-private-key"" cols="100" rows="3" disabled><?=$privateKey?></textarea>
    <br>
    <button onclick="document.getElementById('js-private-key').value = pemToText(document.getElementById('js-private-key').value);">Transfer to Text</button>
    <p>Public Key</p>
    <textarea name="" id="js-public-key"" cols="100" rows="3" disabled><?=$publicKey?></textarea>
    <br>
    <button onclick="document.getElementById('js-public-key').value = pemToText(document.getElementById('js-public-key').value);">Transfer to Text</button>
    
    <hr>
    <h1>OpenSSL Command</h1>
    <input type="text" size="110" disabled value="$ openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext.bin -pubin -inkey public-key-x509.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1">
    <input type="text" size="110" disabled value="$ openssl pkeyutl -decrypt -in ciphertext.bin -out decrypted.txt -inkey private-key.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1">
    <hr>
    
    <h1>PHP</h1>
    <p>Plaintext</p>
    <textarea name="" id="" cols="100" rows="1" disabled><?=$plaintext?></textarea>
    <p>Ciphertext (Base64)</p> 
    <textarea name="" id="" cols="100" rows="2" disabled><?=$cipthertextB64?></textarea>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="" cols="100" rows="1" disabled><?=$decrypted?></textarea>
    <p>Decrypted from JS ciphertext <font color="gray">(<?php if(isset($decryptedForJS)): ?>JS Cipher sent<?php else: ?>No data sent yet<?php endif ?>)</font></p> 
    <textarea name="" id="" cols="100" rows="1" disabled><?=isset($decryptedForJS) ? $decryptedForJS : null?></textarea>

    <hr>

    <form action="" method="POST"> 
        <h1>Javascript</h1>
        <p>Plaintext</p>
        <textarea name="js_plaintext" id="js-plaintext" cols="100" rows="1"><?=$plaintext?></textarea>
        <p>Ciphertext (Base64)</p> 
        <textarea name="js_ciphertext" id="js-ciphertext" cols="100" rows="2"></textarea>
        <p>Decrypted Plaintext</p> 
        <textarea name="" id="js-decrypted" cols="100" rows="1" disabled></textarea>
        <p>Decrypted from PHP ciphertext</p> 
        <textarea name="" id="js-decrypted-from-php" cols="100" rows="1" disabled></textarea>
        <br><br>
        <button type="button" onclick="send(this.form)">Encrypt again then send to PHP</button>
        <button type="button" onclick="send(this.form, true)">Send current cipher to PHP</button>
        <button type="button" onclick="location.href=''">Reset</button>
    </form>  
    
    <script>
        
        var cipherTextFromPHP = "<?=$cipthertextB64?>";

        function send(form, cipherOnly=false) {
            
            if (cipherOnly) {
                form.submit();
                return;
            }

            process().then(result => {
                form.submit();
            });
            return;
        }

        function pemToText(pemString) {
            return pemString.replace(/^-.*\n|\n.*-$/g, '').replace(/\n/g, "");
        }

        function pemToDer(pemString) {
            const pemContent = pemString.replace(/^-.*\n|\n.*-$/g, '').replace(/\n/g, "");
            // base64 decode the string to get the binary data
            console.log(pemContent)
            const binaryDerString = window.atob(pemContent);
            // str2ab
            const buf = new ArrayBuffer(binaryDerString.length);
            const bufView = new Uint8Array(buf);
            for (let i = 0, strLen = binaryDerString.length; i < strLen; i++) {
                bufView[i] = binaryDerString.charCodeAt(i);
            }
            return buf;
        }

        async function importKey(pemKey, keyUsages=["encrypt", "decrypt"]) {    
            const binaryDer = await pemToDer(pemKey);
            try {
                return await crypto.subtle.importKey(
                    "spki",
                    binaryDer,
                    { 
                        name: 'RSA-OAEP', 
                        modulusLength: 2048, //can be 1024, 2048, or 4096
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: {
                            name: "SHA-256"
                        }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                        mgf: { name: "MGF1", hash: { name: "SHA1" } }
                    },
                    false,
                    keyUsages,
                );
            } catch (error) {
                console.log(error)
                throw error;
            }
        }

        async function importPrivateKey(pemKey) {
            const binaryDer = await pemToDer(pemKey);
            try {
                return await crypto.subtle.importKey(
                    "pkcs8",
                    binaryDer,
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048, //can be 1024, 2048, or 4096
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: {
                            name: "SHA-256"
                        }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                        mgf: { name: "MGF1", hash: { name: "SHA-256" } },
                    },
                    false,
                    ["decrypt"],
                );
            } catch (error) {
                console.log(error)
                throw error;
            }
        }

        function encryptData(publicKey, data) {
            return new Promise(function (resolve, reject) {
                crypto.subtle.encrypt(
                    {
                        name: 'RSA-OAEP'
                    },
                    publicKey,
                    new TextEncoder().encode(data)
                ).then(function (encrypted) {
                    // 將加密後的 ArrayBuffer 傳遞給下一個 then
                    base64CipherText = btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
                    resolve(base64CipherText);
                }).catch(function (error) {
                    reject(error);
                });
            });
        }

        function decryptData(key, data) {
            return new Promise(function (resolve, reject) {
                crypto.subtle.decrypt(
                    {
                        name: 'RSA-OAEP',
                    },
                    key,
                    data
                ).then(function (decryptedBuffer) {
                    decrypted = new TextDecoder().decode(decryptedBuffer);
                    resolve(decrypted);
                }).catch(function (error) {
                    reject(error);
                });
            });
        }

        async function process() {
            try {
                
                var plaintext = document.getElementById("js-plaintext").value;
                var publicKey = document.getElementById("js-public-key").value;
                var privateKey = document.getElementById("js-private-key").value;

                // Forge (Support MGF1 with SHA-1)
                var privateKeyObj = forge.pki.privateKeyFromPem(privateKey);
                var publicKeyObj = forge.pki.publicKeyFromPem(publicKey);

                // Encrypt
                var encrypted = publicKeyObj.encrypt(forge.util.createBuffer(plaintext, 'utf8').bytes(), 'RSA-OAEP', {
                    md: forge.md.sha256.create(),
                    mgf1: {
                        md: forge.md.sha1.create()
                    }
                });

                var encryptedData = forge.util.encode64(encrypted);
                console.log("Encrypted Data (Base64):", encryptedData);

                // Decrypt
                var decrypted = privateKeyObj.decrypt(encrypted, 'RSA-OAEP', {
                    md: forge.md.sha256.create(),
                    mgf1: {
                        md: forge.md.sha1.create()
                    }
                });
                var decryptedData = forge.util.decodeUtf8(decrypted);
                console.log("Decrypted Data:", decryptedData);

                // var publicKeyObj = await importKey(publicKey, ["encrypt"]);
                // await pemToDer(privateKey)
                // var privateKeyObj = await importPrivateKey(privateKey);
                // const encryptedData = await encryptData(publicKeyObj, plaintext);
                // console.log('Encrypted Data:', encryptedData);
                // const decryptedData = await decryptData(privateKeyObj, Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0)));
                // console.log('Decrypted Data:', decryptedData);
                var decryptedDataForPHP = "";
                try {
                    decrypted = privateKeyObj.decrypt(forge.util.decode64(cipherTextFromPHP), 'RSA-OAEP', {
                        md: forge.md.sha256.create(),
                        mgf1: {
                            md: forge.md.sha1.create()
                        }
                    });
                    var decryptedDataForPHP = forge.util.decodeUtf8(decrypted);
                    console.log('Decrypted Data for PHP:', decryptedDataForPHP);
                } catch (error) {
                    console.log(error);
                }

                document.getElementById("js-ciphertext").value = encryptedData;
                document.getElementById("js-decrypted").innerHTML = decryptedData;
                document.getElementById("js-decrypted-from-php").innerHTML = decryptedDataForPHP;

            } catch (error) {
                console.error(error.stack);
            }
        }
    
        process();
        
    </script>
</body>
</html>
