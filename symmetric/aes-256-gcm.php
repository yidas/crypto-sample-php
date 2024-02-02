<?php

ini_set("display_errors", 1);
error_reporting(E_ALL);

/**
 * Simple Encryption
 */

// Setting
$cipher ="aes-256-gcm";
$key = '12345678901234567890123456789012';
$tag = null;

/**
 * Decrpyt from JS cipher & IV
 */
if ($_POST) {

    // Data fetching
    $jsCipherText = isset($_POST['js_ciphertext']) ? $_POST['js_ciphertext'] : '';
    $ivFromJS = isset($_POST['js_iv']) ? $_POST['js_iv'] : '';
    
    // Decoding
    $chiperRawFromJs = base64_decode($jsCipherText);

    // Decryption
    // $chiperRaw = openssl_encrypt("message to be encrypted", $cipher, $key, 0, $ivFromJS, $tag);
    $iv = $ivFromJS;
    $chiperCgmBody = substr($chiperRawFromJs, 0, -16);
    $authTag = substr($chiperRawFromJs, -16);
    $jsOriginalPlaintext = openssl_decrypt($chiperCgmBody, $cipher, $key, OPENSSL_RAW_DATA, $iv, $authTag); 
    // var_dump($ivFromJS);var_dump($jsCipherText);var_dump($jsOriginalPlaintext);exit;
}


// Encryption
$plaintext = "message to be encrypted 中文";

// $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
$iv = "123456789012";
$ivText = base64_encode($iv);
$chiperRaw = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
$chiperRaw = $chiperRaw.$tag;
$ciphertext = trim(base64_encode($chiperRaw));
$cipherHex = bin2hex($chiperRaw);

// Decryption
$iv = base64_decode($ivText);
$chiperRaw = base64_decode($ciphertext);
$chiperCgmBody = substr($chiperRaw, 0, -16);
$authTag = substr($chiperRaw, -16);
$originalPlaintext = openssl_decrypt($chiperCgmBody, $cipher, $key, OPENSSL_RAW_DATA, $iv, $authTag); 
// var_dump($iv);var_dump($tag);var_dump($ciphertext);var_dump($originalPlaintext);exit;

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
</head>
<body>
    
    <p>Key</p>
    <input type="text" size="100" value="<?=$key?>" disabled>
    
    <h1>PHP</h1>
    <p>Plaintext</p>
    <textarea name="" id="" cols="100" rows="1" disabled><?=$plaintext?></textarea>
    <p>Ciphertext (Base64)</p> 
    <textarea name="" id="" cols="100" rows="2" disabled><?=$ciphertext?></textarea>
    <p>IV (Text)</p> 
    <input type="text" size="100" value="<?=$iv?>" disabled>
    <!-- <p>IV Text (Base64)</p> 
    <textarea name="" id="" cols="100" rows="1" readonly><?=$ivText?></textarea> -->
    <p>Auth Tag (Base64)</p> 
    <input type="text" size="100" value="<?=base64_encode($tag)?>" disabled>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="" cols="100" rows="1" disabled><?=$originalPlaintext?></textarea>
    <p>Decrypted from JS ciphertext <font color="gray">(<?php if(isset($jsOriginalPlaintext)): ?>JS Cipher sent<?php else: ?>No data sent yet<?php endif ?>)</font></p> 
    <textarea name="" id="" cols="100" rows="1" disabled><?=isset($jsOriginalPlaintext) ? $jsOriginalPlaintext : null?></textarea>

    <hr>

    <form action="" method="POST"> 
        <h1>Javascript</h1>
        <p>Plaintext</p>
        <textarea name="js_plaintext" id="js-plaintext" cols="100" rows="1"><?=$plaintext?></textarea>
        <p>Ciphertext (Base64)</p> 
        <textarea name="js_ciphertext" id="js-ciphertext" cols="100" rows="2" readonly></textarea>
        <p>IV (Text)</p> 
        <input type="text" name="js_iv" id="js-iv"  size="100" value="">
        <p>Decrypted Plaintext</p> 
        <textarea name="" id="js-decrypted" cols="100" rows="1" disabled></textarea>
        <p>Decrypted from PHP ciphertext</p> 
        <textarea name="" id="js-decrypted-from-php" cols="100" rows="1" disabled></textarea>
        <br><br>
        <button type="button" onclick="send(this.form)">Send Cipher & IV to PHP for Decrypting</button>
        <button type="button" onclick="location.href=''">Reset</button>
    </form>  
    
    <script>
        
        var cipherTextFromPHP = "<?=$ciphertext?>";
        var key = "<?=$key?>";
        // var keyObj = CryptoJS.enc.Utf8.parse(key);
        // IV from PHP
        var ivFromPHP = "<?=$ivText?>";
        var iv = "123456789012";
        var base64CipherText;

        function send(form) {
            
            process().then(result => {
                form.submit();
            });
            return;
        }

        function importKey(key) {
            return new Promise(function (resolve, reject) {
                crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode(key),
                    { name: 'AES-GCM' },
                    false,
                    ["encrypt", "decrypt"],
                ).then(function (keyObj) {
                    resolve(keyObj);
                }).catch(function (error) {
                    reject(error);
                });
            });
        }

        function encryptData(key, ivString, data) {
            return new Promise(function (resolve, reject) {
                crypto.subtle.encrypt(
                    {
                        name: 'AES-GCM',
                        iv: new TextEncoder().encode(ivString)
                    },
                    key,
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

        function decryptData(key, ivString, data) {
            return new Promise(function (resolve, reject) {
                crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: new TextEncoder().encode(ivString)
                    },
                    key,
                    data
                ).then(function (decrypted) {
                    $string = new TextDecoder().decode(decrypted);
                    resolve($string);
                }).catch(function (error) {
                    reject(error);
                });
            });
        }

        async function process() {
            try {
                
                var plaintext = document.getElementById("js-plaintext").value;
                var cryptoKey = await importKey(key);
                const encryptedData = await encryptData(cryptoKey, iv, plaintext);
                console.log('Encrypted Data:', encryptedData);
                const decryptedData = await decryptData(cryptoKey, iv, Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0)));
                console.log('Decrypted Data:', decryptedData);
                var decryptedDataForPHP = "";
                try {
                    decryptedDataForPHP = await decryptData(cryptoKey, atob(ivFromPHP), Uint8Array.from(atob(cipherTextFromPHP), c => c.charCodeAt(0)));
                    console.log('Decrypted Data for PHP:', decryptedDataForPHP);
                } catch (error) {
                    console.log(error);
                }

                document.getElementById("js-ciphertext").value = base64CipherText;
                document.getElementById("js-iv").value = iv;
                // document.getElementById("js-salt").innerHTML = encrypted.salt.toString();
                document.getElementById("js-decrypted").innerHTML = decryptedData;
                document.getElementById("js-decrypted-from-php").innerHTML = decryptedDataForPHP;

            } catch (error) {
                console.error('Error:', error);
            }
        }
    
        process();

        // crypto.subtle.importKey(
        //     "raw",
        //     new TextEncoder().encode(key),
        //     { name: 'AES-GCM' },
        //     false,
        //     ["encrypt", "decrypt"],
        // ).then(function (keyObj) {

        //     crypto.subtle.encrypt(
        //         {
        //             name: 'AES-GCM',
        //             iv: new TextEncoder().encode(iv)
        //         },
        //         keyObj,
        //         new TextEncoder().encode(plaintext)
        //     ).then(function (encrypted) {
        //         // encrypted 是一個 ArrayBuffer 包含加密後的資料
        //         // console.log(new Uint8Array(encrypted));
        //         base64CipherText = btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
        //         console.log(base64CipherText);
        //     }).catch(function (error) {
        //         console.error(error);
        //     });
        // });
        // Default mode is CBC, giving self-created IV with default padding 
        // var encrypted = CryptoJS.AES.encrypt(plaintext, keyObj, {
        //     iv: CryptoJS.enc.Hex.parse('f0b53b2da041fca49ef0b9839060b345'),
        // });
        // console.log(encrypted);

        
    </script>
</body>
</html>
