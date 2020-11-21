//
//  Gen.swift
//  AES
//
//  Created by Roman on 20.11.2020.
//

import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
#elseif os(Linux)
import OpenSSL
#endif

func generateBytes(withCount count: Int) throws -> [UInt8] {

    var bytes = Array<UInt8>(repeating: 0, count: count)

    #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)

    let status = CCRandomGenerateBytes(&bytes, count)

    guard status == kCCSuccess else {
        let reason = "CCRandomGenerateBytes returned unexpected status code"
        throw CommonCryptoError(status: status, reason: reason)
    }

    #elseif os(Linux)

    let status = RAND_bytes(&bytes, Int32(count))

    guard status == 1 else {
        throw OpenSSLError(code: ERR_get_error())
    }

    #endif

    return bytes
}
