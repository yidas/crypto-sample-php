<?php

error_reporting(E_ALL);
ini_set("display_errors", 1);

/**
 * Simple Encryption
 */

// Setting
$cipher ="AES-256-CBC";
$key = 'd41d8cd98f00b204e9800998ecf8427e';


/**
 * Decrpyt from JS cipher & IV
 */
if ($_POST) {

    // Data fetching
    $jsCipherText = isset($_POST['js_cipher_text']) ? $_POST['js_cipher_text'] : '';
    $ivHex = isset($_POST['js_iv']) ? $_POST['js_iv'] : '';

    // Decoding
    $chiperRaw = base64_decode($jsCipherText);
    $iv = hex2bin($ivHex);

    // Decryption
    $jsOriginalPlaintext = openssl_decrypt($chiperRaw, $cipher, $key, OPENSSL_RAW_DATA, $iv);
}


// Encryption
$plaintext = "message to be encrypted";

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
    <textarea name="" id="" cols="100" rows="1" readonly><?=$plaintext?></textarea>
    <p>Key</p>
    <textarea name="" id="" cols="100" rows="1" readonly><?=$key?></textarea>
    
    <h1>PHP</h1>
    <p>Cipher Text</p> 
    <textarea name="" id="" cols="100" rows="2" readonly><?=$ciphertext?></textarea>
    <!-- <p>IV Text</p> 
    <textarea name="" id="" cols="100" rows="1" readonly><?=$iv?></textarea> -->
    <p>IV Text (Base64)</p> 
    <textarea name="" id="" cols="100" rows="1" readonly><?=$ivText?></textarea>
    <p>Decrypted Plaintext</p> 
    <textarea name="" id="" cols="100" rows="1" readonly><?=$originalPlaintext?></textarea>
    <p>Decrypted from JS cipher text <font color="gray">(<?php if(isset($jsOriginalPlaintext)): ?>JS Cipher sent<?php else: ?>No data sent yet<?php endif ?>)</font></p> 
    <textarea name="" id="" cols="100" rows="1" readonly><?=isset($jsOriginalPlaintext) ? $jsOriginalPlaintext : null?></textarea>

    <hr>

    <form action="" method="POST"> 
        <h1>Javascript</h1>
        <p>Cipher Text</p> 
        <textarea name="js_cipher_text" id="js-cipher-text" cols="100" rows="2"></textarea>
        <p>IV Text (Hex)</p> 
        <textarea name="js_iv" id="js-iv" cols="100" rows="1"></textarea>
        <p>Salt (Hex) <font color="gray">(Salt would be auto-created by default method without params)</font></p> 
        <textarea name="" id="js-salt" cols="100" rows="1" disabled></textarea>
        <p>Decrypted Plaintext</p> 
        <textarea name="" id="js-decrypted" cols="100" rows="1" readonly></textarea>
        <p>Decrypted from PHP cipher text</p> 
        <textarea name="" id="js-decrypted-from-php" cols="100" rows="1" readonly></textarea>
        <br><br>
        <button type="submit">Send Cipher & IV to PHP for Decrypting</button>
        <button type="button" onclick="location.href=''">Reset</button>
    </form>  
    
    <script>
        
        var plaintext = "<?=$plaintext?>";
        var key = "<?=$key?>";
        var keyObj = CryptoJS.enc.Utf8.parse(key);
        // IV from PHP
        var iv = "<?=$ivText?>";
        
        // Default mode is CBC, giving self-created IV with default padding 
        var encrypted = CryptoJS.AES.encrypt(plaintext, keyObj, {
            iv: CryptoJS.enc.Hex.parse('f0b53b2da041fca49ef0b9839060b345'),
        });
        console.log(encrypted);

        // Giving IV from encrypt data
        var decrypted = CryptoJS.AES.decrypt(encrypted, keyObj, {
            iv: CryptoJS.enc.Hex.parse(encrypted.iv.toString()),
        });

        // Decrypt from PHP
        // Custom IV input by parameter with default CBC mode
        var decryptedFromPHP = CryptoJS.AES.decrypt("<?=$ciphertext?>", keyObj, { 
            // mode: CryptoJS.mode.CBC, 
            iv: CryptoJS.enc.Base64.parse(iv),
        });

        document.getElementById("js-cipher-text").innerHTML = encrypted.toString();
        document.getElementById("js-iv").innerHTML = encrypted.iv.toString();
        // document.getElementById("js-salt").innerHTML = encrypted.salt.toString();
        document.getElementById("js-decrypted").innerHTML = decrypted.toString(CryptoJS.enc.Utf8);;
        document.getElementById("js-decrypted-from-php").innerHTML = decryptedFromPHP.toString(CryptoJS.enc.Utf8);
    </script>
</body>
</html>
