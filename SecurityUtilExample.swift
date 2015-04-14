//  SecurityUtilExample.swift
//
//  Copyright (c) 2015 Wirawit Rueopas
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

import Foundation

class SecurityUtilExample {
    
    func example(){
        Hashing()
        Encryption()
        Decryption()
    }
    
    //MARK:- HASHING
    
    /* In PHP 
    
        $hashedStringInHex = hash_hmac('sha256', "textToBeHashed", "key");
    
    */
    
    func Hashing(){
        let security = SecurityUtil()
        
        //HMAC with SHA256
        let hashedData : NSData = security.HMAC_SHA256("textToBeHashed", hmac_key: "key")!
        let hashedStringInHex  = hashedData.toHexString().lowercaseString
        
        println("Hashed Text = \(hashedStringInHex)")
    }




    //MARK:- ENCRYPTION
    
    /* In PHP

        $plaintext = "textToBeEncrypted";
    
        # USE PKCS7 PADDING (AS IN iOS)
        $padding = 16 - (strlen($plaintext) % 16);
        $plaintextPKCS7 = $plaintext.str_repeat(chr($padding), $padding);

        #USE  plaintextPKCS7
        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,
        $plaintextPKCS7, MCRYPT_MODE_CBC, $iv);
    
        $ciphertext_base64 = base64_encode($ciphertext);
        #To use base64url_encode to handle reserved characters, look at decryption example below.
    
    */

    func Encryption(){
        let security = SecurityUtil()
        
        //AES 256 CBC
        let textData = "textToBeEncrypted".dataUsingEncoding(NSUTF8StringEncoding)!
        
        //Suppose using hashed data as a key for encryption
        let keyData = security.HMAC_SHA256("textToBeHashed", hmac_key: "key") //return NSData 128 bit for AES-256
        let ivData = security.randomIV(16) //return NSData 16 bytes
        let cipherData = security.encryptAES256Data(keyData!, ivData: ivData, plainTextData: textData)
        
        //use base64String to pass to server
        let ivBase64 = ivData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
        let encryptedTextBase64 = cipherData!.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
        
        println("iv in Base64 = \(ivBase64)")
        println("Encrypted Text = \(encryptedTextBase64)")
        
        //Example Result :
        //iv in Base64 = 4odNuv5i2btFjsMq+sfk+w==  (random every time)
        //Encrypted Text = JA0vz3M4h2jVtO5MeGKjb00ajmeKBqVOrvpymVQVqRY==
    }
    
    
    
    
    //MARK:- DECRYPTION
    
    /* In PHP

        $base64DecodedText = base64_decode($encryptedText);
        $result = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $base64DecodedText, MCRYPT_MODE_CBC,$iv);

    */
    
    
    func Decryption(){
        let security = SecurityUtil()
        
        //From server : Note that SecurityUtil assumes the server use base64url_encode before sending the encrypted message.
        /*
            #Use this function to encode base64, because + and / and = are reserved  characters and cannot be pass correctly.
            #In this, we replace + with - , replace / with _ , and trim all = .
        
            function base64url_encode($data){
                return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
            }
            function base64url_decode($data) {
                return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
            }
        */
        let ivString = "4odNuv5i2btFjsMq-sfk-w"
        let encryptedText = "JA0vz3M4h2jVtO5MeGKjb00ajmeKBqVOrvpymVQVqRY"
        
        //Our key in the encryption example
        let keyData = security.HMAC_SHA256("textToBeHashed", hmac_key: "key")
        
        //Fix the string before decrypt , as in base64url_decode
        let ivData = NSData.base64URLDecoding(ivString, options: NSDataBase64DecodingOptions.allZeros)
        let responseData = NSData.base64URLDecoding(encryptedText, options: NSDataBase64DecodingOptions.allZeros)
        
        let decrypt = security.decryptAES256Data(keyData!, ivData: ivData, cipherData: responseData)
        let decryptedResponse = NSString(data: decrypt!, encoding: NSUTF8StringEncoding)!
        
        println("Decrypted Response = \(decryptedResponse)")
        //Results : TextToBeEncrypted
    }

}