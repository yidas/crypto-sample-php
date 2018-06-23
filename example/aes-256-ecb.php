<?php

error_reporting(E_ALL);
ini_set("display_errors", 1);

/**
 * Simple Encryption
 */

// Setting
// Same as old rijndael-128 Mode ECB 
$cipher ="AES-256-ECB";

// Encryption
$plaintext = "message to be encrypted";
$key = 'd41d8cd98f00b204e9800998ecf8427e';

$chiperRaw = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA);
$ciphertext = trim(base64_encode($chiperRaw));
$cipherHex = bin2hex($chiperRaw);

// Decryption
$key = 'd41d8cd98f00b204e9800998ecf8427e';
$chiperRaw = base64_decode($ciphertext);
$originalPlaintext = openssl_decrypt($chiperRaw, $cipher, $key, OPENSSL_RAW_DATA);

?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>PHP Encryption</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/mode-ecb.min.js"></script>
</head>
<body>
    
    <p>Plaintext</p>
    <textarea name="" id="" cols="100" rows="1"><?=$plaintext?></textarea>
    <p>Key</p>
    <textarea name="" id="" cols="100" rows="1"><?=$key?></textarea>
    
    <h1>PHP</h1>
    <p>Cipher Text</p> 
    <textarea name="" id="" cols="100" rows="2"><?=$ciphertext?></textarea>
    <!-- <p>Cipher Text (Hex)</p> 
    <textarea name="" id="" cols="100" rows="2"><?=$cipherHex?></textarea> -->
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="" cols="100" rows="1"><?=$originalPlaintext?></textarea>

    <hr>

    <h1>Javascript</h1>
    <p>Cipher Text</p> 
    <textarea name="" id="js-cipher-text" cols="100" rows="2"></textarea>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="js-decrypted" cols="100" rows="1"></textarea>
    <p>Decrypted from PHP cipher text</p> 
    <textarea name="" id="js-decrypted-from-php" cols="100" rows="1"></textarea>
    
    
    <script>
        
        var plaintext = "<?=$plaintext?>";
        var key = "<?=$key?>";
        var KeyObj = CryptoJS.enc.Utf8.parse(key);
        
        var encrypted = CryptoJS.AES.encrypt(plaintext, KeyObj, { 
            mode: CryptoJS.mode.ECB 
        });

        var decrypted = CryptoJS.AES.decrypt(encrypted, KeyObj, { 
            mode: CryptoJS.mode.ECB, 
        });

        var decryptedFromPHP = CryptoJS.AES.decrypt("<?=$ciphertext?>", KeyObj, { 
            mode: CryptoJS.mode.ECB, 
        });

        document.getElementById("js-cipher-text").innerHTML = encrypted.toString();
        document.getElementById("js-decrypted").innerHTML = decrypted.toString(CryptoJS.enc.Utf8);;
        document.getElementById("js-decrypted-from-php").innerHTML = decryptedFromPHP.toString(CryptoJS.enc.Utf8);
    </script>
</body>
</html>
