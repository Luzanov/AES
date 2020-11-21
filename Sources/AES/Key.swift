//
//  Key.swift
//  AESCryptor
//
//  Created by Roman on 08.09.2020.
//

import Foundation

/// AES key.
public struct Key {
    
    /// Raw key bytes.
    public let bytes: [UInt8]
    
    /// Size of key.
    public let size: Size
    
    /// Possible key sizes.
    public enum Size: Int {
        case k128 = 16
        case k192 = 24
        case k256 = 32
    }
    
    /**
     Initialize a new key with raw bytes.
     - Parameters:
        - bytes: A byte array containing key data.
     - Returns: A new AES key.
     - Throws: An Error if key creation failed.
     */
    public init(bytes: [UInt8]) throws {
        guard let size = Size(rawValue: bytes.count) else {
            throw Error(code: .invalidKeySize)
        }
        self.bytes = bytes
        self.size = size
    }
    
    /**
     Initialize a new random key with specified size.
     - Parameters:
        - size: Size of key.
     - Returns: A new AES Key.
     - Throws: An Error if key creation failed.
    */
    public init(size: Size) throws {
        try self.init(bytes: generateBytes(withCount: size.rawValue))
    }
}
