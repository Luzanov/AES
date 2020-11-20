//
//  Error.swift
//  AES
//
//  Created by Roman on 01.09.2020.
//

import Foundation
import ChainedError

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
#elseif os(Linux)
import OpenSSL
#endif

/// AES error
public struct Error: ChainedError {
    
    public let code: Int
    public let reason: String
    public var thrownByError: ChainedError? = nil
    
    public enum Code: Int {
        case invalidKeySize = 1
        case invalidIVSize
        case commonCryptoError
        case openSSLError
    }
    
    init(code: Code) {
        switch code {
        case .invalidKeySize:
            self.reason = "Key size is not valid"
         
        case .invalidIVSize:
            self.reason = "Initialization vector size is not valid"
            
        case .openSSLError:
            self.reason = "OpenSSL error"
            
            #if os(Linux)
            self.thrownByError = OpenSSLError(code: ERR_get_error())
            #endif
            
        case .commonCryptoError:
            fatalError("Invalid code to init error. Use 'init(thrownBy:' instead")
        }
        self.code = code.rawValue
    }
    
    #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
    
    init(thrownBy error: CommonCryptoError) {
        self.code = Code.commonCryptoError.rawValue
        self.reason = "Common Crypto error"
        self.thrownByError = error
    }
    
    #endif
}

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)

/// Common Crypto error
public struct CommonCryptoError: ChainedError {

    public let code: Int
    public let reason: String
    public var thrownByError: ChainedError? = nil

    /// Create error from raw `CCCryptorStatus` value.
    init(status: CCCryptorStatus, reason: String? = nil) {
        self.code = Int(status)

        switch self.code {
        case kCCSuccess:
            fatalError("You may not init CommonCryptoError with kCCSuccess status")

        case kCCOverflow:
            self.reason = "Overflow"

        case kCCInvalidKey:
            self.reason = "Key is not valid"

        case kCCRNGFailure:
            self.reason = "Random Number Generator Err"

        case kCCParamError:
            self.reason = "Illegal parameter value"

        case kCCDecodeError:
            self.reason = "Input data did not decode or decrypt properly"

        case kCCKeySizeError:
            self.reason = "Key size is not valid"

        case kCCMemoryFailure:
            self.reason = "Memory allocation failure"

        case kCCUnimplemented:
            self.reason = "Function not implemented for the current algorithm"

        case kCCAlignmentError:
            self.reason = "Input size was not aligned properly"

        case kCCBufferTooSmall:
            self.reason = "Insufficent buffer provided for specified operation"

        case kCCUnspecifiedError:
            self.reason = "Unspecified error"

        case kCCCallSequenceError:
            self.reason = "Call sequence error"

        default:
            self.reason = reason ?? "Unexpected reason"
        }
    }
}

#elseif os(Linux)

/// OpenSSL error
public struct OpenSSLError: ChainedError {
    
    public let code: Int
    public let reason: String
    public let thrownByError: ChainedError? = nil
    
    /// Create error from raw `SSL error code` value.
    init(code: UInt) {
        self.code = Int(code)

        if let ptr = ERR_error_string(code, nil) {
            self.reason = String(cString: ptr)
        } else {
            self.reason = "Unexpected reason"
        }
    }
}

#endif
