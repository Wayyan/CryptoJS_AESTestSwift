//
//  EVP_KDF_Util.swift
//  AESTest4
//
//  Created by Way on 09/05/2024.
//

import CryptoSwift
import Foundation

public class EVP_KDF_Util {
    
    public class func generate_evp_kdf_aes256cbc_key_iv(pass: String, saltData: [UInt8]) throws -> (String, String) {
        
        let passData = [UInt8](pass.data(using: .utf8)!)
        
        let keySize: Int = 32
        let keyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: keySize)
        keyPointer.initialize(repeating: 0, count: keySize)
        
        let ivSize: Int = 16
        let ivPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: ivSize)
        ivPointer.initialize(repeating: 0, count: ivSize)
    
        let err = gen_evp_kdf_aes256cbc1(passData, saltData, keyPointer, ivPointer)
        
//        if err != ECE_OK {
//            throw PushCryptoError.decryptionError(errCode: err)
//        }
        
        let key = Data(bytes: keyPointer, count: keySize).map({ String(format: "%02hhx", $0) }).joined()
        let iv = Data(bytes: ivPointer, count: ivSize).map({ String(format: "%02hhx", $0) }).joined()
        
        return (key, iv)
    }
    
    static func decrypt(_ base64String: String, passwordUtf8: String) throws -> String {
            let encrypted = Data(base64Encoded: base64String)!
            let salt = [UInt8](encrypted[8 ..< 16])
            let evp = try EVP_KDF_Util.generate_evp_kdf_aes256cbc_key_iv(pass: passwordUtf8, saltData: salt) // key + iv
            let aes = try AES(key: Array<UInt8>.init(hex: evp.0),
                              blockMode: CBC(iv: Array<UInt8>.init(hex: evp.1)),
                              padding: .pkcs7)
            let data = [UInt8](encrypted[16 ..< encrypted.count])
            let decrypted = try aes.decrypt(data)
            
            guard let decryptedStr = String(bytes: decrypted, encoding: .utf8) else {
                throw AES.Error.invalidData
            }
            return decryptedStr
        }
}
