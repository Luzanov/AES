//
//  Cryptors.swift
//  AESCryptor
//
//  Created by Roman on 08.09.2020.
//

import Foundation

fileprivate func performUpdate(for cryptor: Cryptor, byteArrayIn: [UInt8]) throws -> [UInt8] {
    let outputLength = cryptor.getOutputLength(inputByteCount: byteArrayIn.count, isFinal: false)
    var byteArrayOut = Array<UInt8>(repeating: 0, count:outputLength)
    
    let dataOutMoved = try cryptor.update(dataIn: byteArrayIn, dataOut: &byteArrayOut)
    
    return Array(byteArrayOut[0..<dataOutMoved])
}

fileprivate func performFinal(for cryptor: Cryptor) throws -> [UInt8] {
    let outputLength = cryptor.getOutputLength(inputByteCount: 0, isFinal: true)
    var byteArrayOut = Array<UInt8>(repeating: 0, count:outputLength)

    let dataOutMoved = try cryptor.final(dataOut: &byteArrayOut)
    
    return Array(byteArrayOut[0..<dataOutMoved])
}


final public class Encryptor {
    
    private let cryptor: Cryptor
    
    public init(key: Key, iv: IV) throws {
        self.cryptor = try Cryptor(operation: .encrypt, key: key, iv: iv)
    }
    
    public func encryptNext(byteArrayIn: [UInt8]) throws -> [UInt8] {
        return try performUpdate(for: self.cryptor, byteArrayIn: byteArrayIn)
    }
    
    public func encryptFinal() throws -> [UInt8] {
        return try performFinal(for: self.cryptor)
    }
    
    public func encrypt(byteArrayIn: [UInt8]) throws -> [UInt8] {
        try self.cryptor.reset()
        let first = try performUpdate(for: self.cryptor, byteArrayIn: byteArrayIn)
        let final = try performFinal(for: self.cryptor)
        return first + final
    }
}

final public class Decryptor {
    
    private let cryptor: Cryptor
    
    public init(key: Key, iv: IV) throws {
        self.cryptor = try Cryptor(operation: .decrypt, key: key, iv: iv)
    }
    
    public func decryptNext(byteArrayIn: [UInt8]) throws -> [UInt8] {
        return try performUpdate(for: self.cryptor, byteArrayIn: byteArrayIn)
    }
    
    public func decryptFinal() throws -> [UInt8] {
        return try performFinal(for: self.cryptor)
    }
    
    public func decrypt(byteArrayIn: [UInt8]) throws -> [UInt8] {
        try self.cryptor.reset()
        let first = try performUpdate(for: self.cryptor, byteArrayIn: byteArrayIn)
        let final = try performFinal(for: self.cryptor)
        return first + final
    }
}
