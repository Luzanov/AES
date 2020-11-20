import XCTest
@testable import AES
@testable import ChainedError

final class AESTests: XCTestCase {
    
    static var allTests = [
        ("testStream", testStream),
        ("testInvalidIV", testInvalidIV),
        ("testInvalidKey", testInvalidKey),
        ("testMemoryLeaks", testMemoryLeaks),
        ("testAllKeysWithAllBytes", testAllKeysWithAllBytes),
    ]
    
    static func testBlock(_ block: () throws -> Void) {
        do {
            try block()
        } catch let error as ChainedError {
            XCTFail(error.description)
        } catch {
            XCTFail("Returned error must always confirm to ChainedError protocol. " + "\(error.localizedDescription)")
        }
    }

    func testStream() {
        AESTests.testBlock {
            let stringPart1 = "The Advanced Encryption Standard (AES), also known by its original name "
            let stringPart2 = "Rijndael is a specification for the encryption of electronic data established "
            let stringPart3 = "by the U.S. National Institute of Standards and Technology (NIST) in 2001"
            let originalString = stringPart1 + stringPart2 + stringPart3

            let dataPart1: [UInt8] = Array(stringPart1.utf8)
            let dataPart2: [UInt8] = Array(stringPart2.utf8)
            let dataPart3: [UInt8] = Array(stringPart3.utf8)

            let key = try Key(size: .k128)
            let iv = try generateBytes(withCount: 16)
            let encryptor = try Encryptor(key: key, iv: iv)
            let decryptor = try Decryptor(key: key, iv: iv)

            let encryptedPart1 = try encryptor.encryptNext(byteArrayIn: dataPart1)
            let encryptedPart2 = try encryptor.encryptNext(byteArrayIn: dataPart2)
            let encryptedPart3 = try encryptor.encryptNext(byteArrayIn: dataPart3)
            let encryptedPart4 = try encryptor.encryptFinal()

            let decryptedPart1 = try decryptor.decryptNext(byteArrayIn: encryptedPart1)
            let decryptedPart2 = try decryptor.decryptNext(byteArrayIn: encryptedPart2)
            let decryptedPart3 = try decryptor.decryptNext(byteArrayIn: encryptedPart3)
            let decryptedPart4 = try decryptor.decryptNext(byteArrayIn: encryptedPart4)
            let decryptedPart5 = try decryptor.decryptFinal()

            let decryptedString1 = String(bytes: decryptedPart1, encoding: .utf8)!
            let decryptedString2 = String(bytes: decryptedPart2, encoding: .utf8)!
            let decryptedString3 = String(bytes: decryptedPart3, encoding: .utf8)!
            let decryptedString4 = String(bytes: decryptedPart4, encoding: .utf8)!
            let decryptedString5 = String(bytes: decryptedPart5, encoding: .utf8)!

            let decriptedString = decryptedString1 + decryptedString2 + decryptedString3 + decryptedString4 + decryptedString5

            XCTAssertEqual(originalString, decriptedString)
        }
    }
    
    func testInvalidIV() {
        AESTests.testBlock {
            let key = try Key(size: .k128)
            let invalidIV = try generateBytes(withCount: 17)
            
            XCTAssertThrowsError(try Encryptor(key: key, iv: invalidIV)) {
                if let error = $0 as? AES.Error {
                    XCTAssertEqual(error.code, Error.Code.invalidIVSize.rawValue)
                } else {
                    XCTFail("Wrong error type")
                }
            }
        }
    }
    
    func testInvalidKey() {
        XCTAssertThrowsError(try Key(bytes: [1,2,3])) {
            if let error = $0 as? AES.Error {
                XCTAssertEqual(error.code, Error.Code.invalidKeySize.rawValue)
            } else {
                XCTFail("Wrong error type")
            }
        }
    }
    
    func testAllKeysWithAllBytes() {
        AESTests.testBlock {
            let defaultKey = try Key(bytes: [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5])
            let zero128Key = try Key(bytes: Array<UInt8>(repeating: 0, count: 16))
            let zero192Key = try Key(bytes: Array<UInt8>(repeating: 0, count: 24))
            let zero256Key = try Key(bytes: Array<UInt8>(repeating: 0, count: 32))
            let rnd128Key = try Key(size: .k128)
            let rnd192Key = try Key(size: .k192)
            let rnd256Key = try Key(size: .k256)

            let noBytes: [UInt8] = []
            let oneByte: [UInt8] = [245]
            let zeroBytes3: [UInt8] = Array<UInt8>(repeating: 0, count: 3)
            let zeroBytes11: [UInt8] = Array<UInt8>(repeating: 0, count: 11)
            let zeroBytes255: [UInt8] = Array<UInt8>(repeating: 0, count: 255)
            let zeroBytes3000: [UInt8] = Array<UInt8>(repeating: 0, count: 300)
            let rndByte: [UInt8] = try generateBytes(withCount: 1)
            let rndBytes4: [UInt8] = try generateBytes(withCount: 4)
            let rndBytes16: [UInt8] = try generateBytes(withCount: 16)
            let rndBytes768: [UInt8] = try generateBytes(withCount: 768)
            let rndBytes5000: [UInt8] = try generateBytes(withCount: 5000)

            let iv: [UInt8] = [2,23,49,15,4,94,56,9,0,1,23,23,34,34,34,8]
            let rndIv1: [UInt8] = try generateBytes(withCount: 16)
            let rndIv2: [UInt8] = try generateBytes(withCount: 16)
            let rndIv3: [UInt8] = try generateBytes(withCount: 16)
            
            let keys: [Key] = [
                defaultKey,
                zero128Key,
                zero192Key,
                zero256Key,
                rnd128Key,
                rnd192Key,
                rnd256Key
            ]

            let bytesArray: [Array<UInt8>] = [
                noBytes,
                oneByte,
                zeroBytes3,
                zeroBytes11,
                zeroBytes255,
                zeroBytes3000,
                rndByte,
                rndBytes4,
                rndBytes16,
                rndBytes768,
                rndBytes5000
            ]
            
            let ivArray:  [Array<UInt8>] = [iv, rndIv1, rndIv2, rndIv3]

            for bytes in bytesArray {
                for iv in ivArray {
                    for key in keys {
                        let encryptor = try Encryptor(key: key, iv: iv)
                        let decryptor = try Decryptor(key: key, iv: iv)

                        let encrypted = try encryptor.encrypt(byteArrayIn: bytes)
                        let decrypted = try decryptor.decrypt(byteArrayIn: encrypted)

                        XCTAssertEqual(bytes, decrypted)
                    }
                }
            }
        }
    }
    
    func testMemoryLeaks() {
        AESTests.testBlock {
            /*
            while true {
                try autoreleasepool {
                    let key = try Key(size: .k256)
                    let iv = try generateBytes(withCount: 16)
                    let bytes = try generateBytes(withCount: 146)
                    
                    let encryptor = try Encryptor(key: key, iv: iv)
                    let decryptor = try Decryptor(key: key, iv: iv)

                    let encrypted = try encryptor.encrypt(byteArrayIn: bytes)
                    let decrypted = try decryptor.decrypt(byteArrayIn: encrypted)

                    XCTAssertEqual(bytes, decrypted)
                }
                usleep(1000)
            }
            */
        }
    }
}
