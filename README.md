# SecurityUtil
HMAC with SHA256 and AES-256 CBC, PKCS7Padding for Swift (compatible with PHP) 

***Based on PHP***
- hash_hmac('sha256' ...) 
- mcrypt_decrypt(MCRYPT_RIJNDAEL_128 ... MCRYPT_MODE_CBC)
- NSData extension to decode base64url_encode in php from server (replace '+' with '-' , '/' with '_' and trim '=' )


NOTE : The goal of this small file is to use those two functions in few lines of code and as a guide on how to do it for beginner like me.

###Usage :

-Drop this swift file in your project to use or do it anyway you want. 

###Examples : 

At its core :

**Hash **

```swift
    let hashedData : NSData = SecurityUtil().HMAC_SHA256("textToBeHashed", hmac_key: "key")!
```
**Encryption **

```swift
    let cipherData = SecurityUtil().encryptAES256Data(keyData, ivData: ivData, plainTextData: textData)
```
**Decryption **

```swift
    let decryptedData = security.decryptAES256Data(keyData, ivData: ivData, cipherData: cipherData)
```

-Look at the working example file for more details and how to use.

-Also contains some PHP codes in comments for a comparison.

