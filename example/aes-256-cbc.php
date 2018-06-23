<?php

error_reporting(E_ALL);
ini_set("display_errors", 1);

/**
 * Simple Encryption
 */

// Setting
$cipher ="AES-256-CBC";

// Encryption
$plaintext = "message to be encrypted";
$key = 'd41d8cd98f00b204e9800998ecf8427e';

$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
$ivText = base64_encode($iv);
$chiperRaw = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
$ciphertext = trim(base64_encode($chiperRaw));
$cipherHex = bin2hex($chiperRaw);

// Decryption
$key = 'd41d8cd98f00b204e9800998ecf8427e';
$iv = base64_decode($ivText);
$chiperRaw = base64_decode($ciphertext);
$originalPlaintext = openssl_decrypt($chiperRaw, $cipher, $key, OPENSSL_RAW_DATA, $iv);

?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>PHP Encryption</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>

    <!-- Padding Libraries -->
    <!-- <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-zeropadding-min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-nopadding-min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-ansix923-min.js"></script> -->
</head>
<body>
    
    <p>Plaintext</p>
    <textarea name="" id="" cols="100" rows="1"><?=$plaintext?></textarea>
    <p>Key</p>
    <textarea name="" id="" cols="100" rows="1"><?=$key?></textarea>
    
    <h1>PHP</h1>
    <p>Cipher Text</p> 
    <textarea name="" id="" cols="100" rows="2"><?=$ciphertext?></textarea>
    <p>IV Text (Base64)</p> 
    <textarea name="" id="" cols="100" rows="1"><?=$ivText?></textarea>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="" cols="100" rows="1"><?=$originalPlaintext?></textarea>

    <hr>

    <h1>Javascript</h1>
    <p>Cipher Text</p> 
    <textarea name="" id="js-cipher-text" cols="100" rows="2"></textarea>
    <p>IV Text (Hex)</p> 
    <textarea name="" id="js-iv" cols="100" rows="1"></textarea>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="js-decrypted" cols="100" rows="1"></textarea>
    <p>Decrypted from PHP cipher text</p> 
    <textarea name="" id="js-decrypted-from-php" cols="100" rows="1"></textarea>
    
    
    <script>
        
        var plaintext = "<?=$plaintext?>";
        var key = "<?=$key?>";
        var KeyObj = CryptoJS.enc.Utf8.parse(key);
        var iv = "<?=$ivText?>";
        
        // Default mode is CBC, IV would be auto-created in encrypted object
        var encrypted = CryptoJS.AES.encrypt(plaintext, key);
        console.log(encrypted);

        // The encrypted object includes IV, padding info to decrypt
        var decrypted = CryptoJS.AES.decrypt(encrypted, key);

        // Custom IV input by parameter with default CBC mode
        var decryptedFromPHP = CryptoJS.AES.decrypt("<?=$ciphertext?>", KeyObj, { 
            // mode: CryptoJS.mode.CBC, 
            iv: CryptoJS.enc.Base64.parse(iv),
        });

        document.getElementById("js-cipher-text").innerHTML = encrypted.toString();
        document.getElementById("js-iv").innerHTML = encrypted.iv.toString();
        document.getElementById("js-decrypted").innerHTML = decrypted.toString(CryptoJS.enc.Utf8);;
        document.getElementById("js-decrypted-from-php").innerHTML = decryptedFromPHP.toString(CryptoJS.enc.Utf8);
    </script>
</body>
</html>
