//  SecurityUtil.swift
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

class SecurityUtil {
    
    //MARK:- HMAC (SHA256)
    func HMAC_SHA256(text : String , hmac_key:String)->NSData?{
        if let message = text.dataUsingEncoding(NSUTF8StringEncoding)?.bytes() {
            if let keyBytes = hmac_key.dataUsingEncoding(NSUTF8StringEncoding)?.bytes(){
                let result = self.hmac_hash(keyBytes, message: message)
                let data = NSData.withBytes(result!)
                return data
            }
        }
        return nil
    }
    func SHA256(data : NSData)->NSData{
        var hash = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
        CC_SHA256(data.bytes, CC_LONG(data.length), &hash)
        return NSData.withBytes(hash)
    }
    func SHA256(text : String)->String{
        var data = text.dataUsingEncoding(NSUTF8StringEncoding)!
        let hash = self.SHA256(data)
        return NSString(data: hash, encoding: NSUTF8StringEncoding) as! String
    }
    private func hmac_hash(keyBytes : [UInt8] , message:[UInt8]) -> [UInt8]? {
        var opad = [UInt8](count: 64, repeatedValue: 0x5c)
        for (idx, val) in enumerate(keyBytes) {
            opad[idx] = keyBytes[idx] ^ opad[idx]
        }
        var ipad = [UInt8](count: 64, repeatedValue: 0x36)
        for (idx, val) in enumerate(keyBytes) {
            ipad[idx] = keyBytes[idx] ^ ipad[idx]
        }
        
        var finalHash:[UInt8]? = nil;
        let temp1 = NSData.withBytes(ipad + message)
        let ipadAndMessageHash = SHA256(temp1).bytes()
        let temp2 = NSData.withBytes(opad + ipadAndMessageHash)
        finalHash = SHA256(temp2).bytes();
        
        return finalHash
    }
    //MARK:- AES256 CBC
    func encryptAES256Data(keyData : NSData , ivData : NSData , plainTextData : NSData)->NSData?{
        let keyBytes         = UnsafePointer<UInt8>(keyData.bytes)
        let keyLength        = size_t(kCCKeySizeAES256)
        
        let dataLength    = Int(plainTextData.length)
        let dataBytes     = UnsafePointer<UInt8>(plainTextData.bytes)
        
        var bufferData    = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)!
        var bufferPointer = UnsafeMutablePointer<UInt8>(bufferData.mutableBytes)
        let bufferLength  = size_t(bufferData.length)
        
        let operation: CCOperation = UInt32(kCCEncrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES)
        let options = UInt32(kCCOptionPKCS7Padding)
        
        let ivPointer = UnsafePointer<UInt8>(ivData.bytes)
        
        var numBytesEncrypted: Int = 0
        
        var cryptStatus = CCCrypt(operation, algoritm, options, keyBytes, keyLength, ivPointer, dataBytes, dataLength, bufferPointer, bufferLength, &numBytesEncrypted)
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            let data = NSData(bytes: bufferData.mutableBytes, length: Int(numBytesEncrypted))
            return data
        }else{
            return nil
        }
    }
    func decryptAES256Data(keyData : NSData , ivData : NSData , cipherData : NSData)->NSData?
    {
        let keyBytes         = UnsafePointer<UInt8>(keyData.bytes)
        let keyLength        = size_t(kCCKeySizeAES256)
        
        let dataLength    = Int(cipherData.length)
        let dataBytes     = UnsafePointer<UInt8>(cipherData.bytes)
        
        var bufferData    = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)!
        var bufferPointer = UnsafeMutablePointer<UInt8>(bufferData.mutableBytes)
        let bufferLength  = size_t(bufferData.length)
        
        let operation: CCOperation = UInt32(kCCDecrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let options = UInt32(kCCOptionPKCS7Padding)
        
        let ivPointer = UnsafePointer<UInt8>(ivData.bytes)
        
        var numBytesDecrypted: Int = 0
        
        var cryptStatus = CCCrypt(operation, algoritm, options, keyBytes, keyLength, ivPointer, dataBytes, dataLength, bufferPointer, bufferLength, &numBytesDecrypted)
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            let data = NSData(bytes: bufferData.mutableBytes, length: Int(numBytesDecrypted))
            return data
        }else{
            return nil
        }
    }
    private func randomIV(lengthOfBytes:Int) -> [UInt8] {
        //if sha256 -> use length = 16
        var randomIV:[UInt8] = [UInt8]();
        for (var i = 0; i < lengthOfBytes; i++) {
            randomIV.append(UInt8(truncatingBitPattern: arc4random_uniform(256)));
        }
        return randomIV
    }
    func randomIV(length:Int)->NSData{
        return NSData.withBytes(randomIV( length))
    }
}
extension NSData {
    
    public var hexString: String {
        return self.toHexString()
    }
    
    func toHexString() -> String {
        let count = self.length / sizeof(UInt8)
        var bytesArray = [UInt8](count: count, repeatedValue: 0)
        self.getBytes(&bytesArray, length:count * sizeof(UInt8))
        
        var s = "";
        for byte in bytesArray {
            s = s + String(format: "%02X", byte)
        }
        return s;
    }
    func bytes() -> [UInt8] {
        let count = self.length / sizeof(UInt8)
        var bytesArray = [UInt8](count: count, repeatedValue: 0)
        self.getBytes(&bytesArray, length:count * sizeof(UInt8))
        return bytesArray
    }
    
    ///Decode base64String from the server that string is originally replaced "/" with "_" and "+" with "-" , and trimmed "=" so that it can pass the response to client correctly because those are reserved characters.
    class public func base64URLDecoding(base64EncodedString : String , options : NSDataBase64DecodingOptions )->NSData
    {
        var stringFix = base64EncodedString.stringByReplacingOccurrencesOfString("_", withString: "/", options: NSStringCompareOptions.LiteralSearch, range: nil)
        stringFix = stringFix.stringByReplacingOccurrencesOfString("-", withString: "+", options: NSStringCompareOptions.LiteralSearch, range: nil)
        while count(stringFix)%4 != 0 {
            stringFix += "="
        }
        return NSData(base64EncodedString: stringFix, options: options)!
    }
    class public func withBytes(bytes: [UInt8]) -> NSData {
        return NSData(bytes: bytes, length: bytes.count)
    }
}