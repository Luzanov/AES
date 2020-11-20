//
//  Cryptor.swift
//  AES
//
//  Created by Roman on 01.09.2020.
//

import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
#elseif os(Linux)
import OpenSSL
#endif

class Cryptor {
    
    /// Enumerates Cryptor operations
    enum Operation {
        
        case encrypt
        case decrypt
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        /// Convert to native `CCOperation`
        var nativeValue: CCOperation {
            switch self {
            case .encrypt: return CCOperation(kCCEncrypt)
            case .decrypt: return CCOperation(kCCDecrypt)
            }
        }
        
        #elseif os(Linux)
        
        /// Convert to native value
        var nativeValue: UInt32 {
            switch self {
            case .encrypt: return 0
            case .decrypt: return 1
            }
        }
        
        #endif
    }
    
    
    #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
    
    /// CommonCrypto Context
    private var context = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
    
    #elseif os(Linux)
    
    /// OpenSSL Cipher Context
    private let context: OpaquePointer = EVP_CIPHER_CTX_new()
    
    /// Operation
    private var operation: Operation
    
    /// Key
    private let key: Key
    
    #endif
    
    
    /// Initialization vector
    private let iv: [UInt8]
    
    /**
     Default Initializer.
     - Parameters:
        - operation: Defines the basic operation: .encrypt or .decrypt.
        - key: Raw key material.
     - Returns: New Cryptor instance.
     */
    init(operation: Operation, key: Key, iv: [UInt8]) throws {
        
        guard iv.count == Block.Size.k128.rawValue else {
            throw Error(code: .invalidIVSize)
        }
        self.iv = iv
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        let algorithm = CCAlgorithm(kCCAlgorithmAES)
        let options = CCOptions(kCCOptionPKCS7Padding)
        let status = CCCryptorCreate(operation.nativeValue, algorithm, options, key.bytes, key.size.rawValue, iv, self.context)
        
        guard status == kCCSuccess else {
            throw Error(thrownBy: CommonCryptoError(status: status, reason: "Cryptor init returned unexpected status"))
        }
        
        #elseif os(Linux)
        
        self.key = key
        self.operation = operation
        try self.initOpenSSLContext()
        
        #endif
    }
    
    #if os(Linux)
    
    /// Init OpenSSL Cipher Context
    private func initOpenSSLContext() throws {
        let cipher: OpaquePointer
        
        switch self.key.size {
        case .k128: cipher = EVP_aes_128_cbc()
        case .k192: cipher = EVP_aes_192_cbc()
        case .k256: cipher = EVP_aes_256_cbc()
        }
        
        var status: Int32
        
        switch operation {
        case .encrypt:
            status = EVP_EncryptInit_ex(self.context, cipher, nil, self.key.bytes, iv)
            
        case .decrypt:
            status = EVP_DecryptInit_ex(self.context, cipher, nil, self.key.bytes, iv)
        }
        
        guard status == 1 else {
            throw Error(code: .openSSLError)
        }
        
        status = EVP_CIPHER_CTX_set_padding(self.context, 1)
        
        guard status == 1 else {
            throw Error(code: .openSSLError)
        }
    }
    #endif
    
    /// Cleanup
    deinit {
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        let status = CCCryptorRelease(self.context.pointee)
        
        if status != kCCSuccess {
            NSLog("WARNING: CCCryptoRelease failed with status \(status).")
        }
        
        self.context.deallocate()
        
        #elseif os(Linux)
        
        EVP_CIPHER_CTX_free(self.context)
        
        #endif
    }
    
    /**
     Update the buffer.
     - Parameters:
        - dataIn: Input data bytes.
        - dataOut: Result is written here.
     - Returns: The number of bytes written to dataOut.
     */
    func update(dataIn: [UInt8], dataOut: inout [UInt8]) throws -> Int {
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        var dataOutMoved = 0
        let status = CCCryptorUpdate(self.context.pointee, dataIn, dataIn.count, &dataOut, dataOut.count, &dataOutMoved)
        
        guard status == kCCSuccess else {
            throw Error(thrownBy: CommonCryptoError(status: status))
        }
        return dataOutMoved
        
        #elseif os(Linux)
        
        var status: Int32
        var length: Int32 = 0
        
        switch self.operation {
        case .encrypt:
            status = EVP_EncryptUpdate(self.context, &dataOut, &length, dataIn, Int32(dataIn.count))
            
        case .decrypt:
            status = EVP_DecryptUpdate(self.context, &dataOut, &length, dataIn, Int32(dataIn.count))
        }
        
        guard status == 1 else {
            throw Error(code: .openSSLError)
        }
        return Int(length)
        
        #endif
    }
    
    
    /**
     Retrieves all remaining encrypted or decrypted data from this cryptor.
     - Parameters:
        - dataOut: Result is written here.
     - Returns: On successful completion, the number of bytes written to the output buffer.
     */
    func final(dataOut: inout [UInt8]) throws -> Int {
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        var dataOutMoved = 0
        let status = CCCryptorFinal(self.context.pointee, &dataOut, dataOut.count, &dataOutMoved)
        
        guard status == kCCSuccess else {
            throw Error(thrownBy: CommonCryptoError(status: status))
        }
        return dataOutMoved
        
        #elseif os(Linux)
        
        var status: Int32
        var length = Int32(dataOut.count)
        
        switch self.operation {
        case .encrypt:
            status = EVP_EncryptFinal_ex(self.context, &dataOut, &length)
            
        case .decrypt:
            status = EVP_DecryptFinal_ex(self.context, &dataOut, &length)
        }
        
        guard status == 1 else {
            throw Error(code: .openSSLError)
        }
        return Int(length)
        
        #endif
    }
    
    /// Reinitializes an existing context.
    func reset() throws {
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        let status = CCCryptorReset(self.context.pointee, self.iv)
        
        guard status == kCCSuccess else {
            throw Error(thrownBy: CommonCryptoError(status: status))
        }
        
        #elseif os(Linux)
        
        let status = EVP_CIPHER_CTX_reset(self.context)
        
        guard status == 1 else {
            throw Error(code: .openSSLError)
        }
        
        try self.initOpenSSLContext()
        
        #endif
    }
    
    /**
     Determines the number of bytes that will be output by this Cryptor if inputBytes of additional data is input.
     - Parameters:
        - inputByteCount: Number of bytes that will be input
        - isFinal: True if buffer to be input will be the last input buffer, false otherwise
     - Returns: The final output length
     */
    func getOutputLength(inputByteCount: Int, isFinal: Bool) -> Int {
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        
        return CCCryptorGetOutputLength(self.context.pointee, inputByteCount, isFinal)
        
        #elseif os(Linux)
        
        let blockSize = Block.Size.k128.rawValue
        
        if inputByteCount == 0 {
            return blockSize
        }
        
        return (inputByteCount + blockSize - (inputByteCount % blockSize))
        
        #endif
    }
}
