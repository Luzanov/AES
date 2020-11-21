//
//  IV.swift
//  AES
//
//  Created by Roman on 21.11.2020.
//

import Foundation

/// Initialization vector.
public struct IV {
    
    /// Raw initialization vector bytes.
    public let bytes: [UInt8]
    
    /**
     Initialize a new initialization vector with raw bytes.
     - Parameters:
        - bytes: A byte array containing initialization vector data.
     - Returns: A new initialization vector.
     - Throws: An Error if initialization vector creation failed.
     */
    public init(bytes: [UInt8]) throws {
        guard bytes.count == Block.Size.k128.rawValue else {
            throw Error(code: .invalidIVSize)
        }
        self.bytes = bytes
    }
    
    /**
     Initialize a new random Initialization vector.
     - Returns: A new initialization vector.
     - Throws: An Error if initialization vector creation failed.
    */
    public init() throws {
        try self.init(bytes: generateBytes(withCount: Block.Size.k128.rawValue))
    }
}
