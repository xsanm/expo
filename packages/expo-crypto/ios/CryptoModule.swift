// Copyright 2022-present 650 Industries. All rights reserved.

import CommonCrypto
import ExpoModulesCore
import CryptoKit

public class CryptoModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoCrypto")

    Class(CryptoKey.self) {
        Constructor { (algorithm: AesKeyGenParams, extractable: Bool, keyUsages: [KeyUsage]) in
            return CryptoKey(algorithm: algorithm, extractable: extractable, keyUsages: keyUsages)
        }
    }

    AsyncFunction("digestStringAsync", digestString)

    Function("digestString", digestString)

    AsyncFunction("getRandomBase64StringAsync", getRandomBase64String)

    Function("getRandomBase64String", getRandomBase64String)

    Function("getRandomValues", getRandomValues)

    Function("digest", digest)

    Function("randomUUID") {
      UUID().uuidString.lowercased()
    }

    Function("encryptAesGcm", encryptAesGcm)

    Function("decryptAesGcm", decryptAesGcm)

    Function("exportKey", exportKey)

   Function("importKey", importKey)

  }
}

internal enum KeyFormat: String, EnumArgument {
  case raw = "raw"
  case pkcs8 = "pkcs8"
  case spki = "spki"
  case jwk = "jwk"
}

internal enum KeyUsage: String, EnumArgument {
  case encrypt = "encrypt"
  case decrypt = "decrypt"
  case sign = "sign"
  case verify = "verify"
  case deriveKey = "deriveKey"
  case deriveBits = "deriveBits"
  case wrapKey = "wrapKey"
  case unwrapKey = "unwrapKey"
}

struct AesKeyGenParams: Record {
  @Field
  var name: AlgorithmName = .gcm

  @Field
  var length: Int = 32

  internal enum AlgorithmName: String, EnumArgument {
    case cbc = "AES-CBC"
    case gcm = "AES-GCM"
  }
}

struct HmacKeyGenParams: Record {
  @Field
  var name: AlgorithmName = .hmac

  internal enum AlgorithmName: String, EnumArgument {
    case hmac = "HMAC"
  }
}

class CryptoKey: SharedObject {
  private var _algorithm: AesKeyGenParams
  private var _extractable: Bool
  private let _keyUsages: [KeyUsage]

  private var algorithm: AesKeyGenParams {
    _algorithm
  }
  private var extractable: Bool {
    _extractable
  }
  var keyUsages: [KeyUsage] {
    _keyUsages
  }

  var secretKey = SymmetricKey(size: .bits256)

  init(algorithm: AesKeyGenParams, extractable: Bool, keyUsages: [KeyUsage]) {
    self._algorithm = algorithm
    self._extractable = extractable
    self._keyUsages = keyUsages
    if algorithm.name == .gcm {
      secretKey = SymmetricKey(size: .bits256)
    }
  }

  func getKey() -> SymmetricKey {
    return secretKey
  }

  func setKey(newKey: SymmetricKey) {
    self.secretKey = newKey
  }

}


private func getRandomBase64String(length: Int) throws -> String {
  var bytes = [UInt8](repeating: 0, count: length)
  let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)

  guard status == errSecSuccess else {
    throw FailedGeneratingRandomBytesException(status)
  }
  return Data(bytes).base64EncodedString()
}

private func digestString(algorithm: DigestAlgorithm, str: String, options: DigestOptions) throws -> String {
  guard let data = str.data(using: .utf8) else {
    throw LossyConversionException()
  }

  let length = Int(algorithm.digestLength)
  var digest = [UInt8](repeating: 0, count: length)

  data.withUnsafeBytes { bytes in
    let _ = algorithm.digest(bytes.baseAddress, UInt32(data.count), &digest)
  }

  switch options.encoding {
  case .hex:
    return digest.reduce("") { $0 + String(format: "%02x", $1) }
  case .base64:
    return Data(digest).base64EncodedString()
  }
}

private func getRandomValues(array: TypedArray) throws -> TypedArray {
  let status = SecRandomCopyBytes(
    kSecRandomDefault,
    array.byteLength,
    array.rawPointer
  )

  guard status == errSecSuccess else {
    throw FailedGeneratingRandomBytesException(status)
  }
  return array
}

private func digest(algorithm: DigestAlgorithm, output: TypedArray, data: TypedArray) {
  let length = Int(algorithm.digestLength)
  let outputPtr = output.rawPointer.assumingMemoryBound(to: UInt8.self)
  algorithm.digest(data.rawPointer, UInt32(data.byteLength), outputPtr)
}

private func encryptAesGcm(key: CryptoKey, data: String, iv: Uint8Array) throws -> String {
  guard key.keyUsages.contains(.encrypt) else {
    throw WrongKeyUsageException()
  }

  //TODO handle invalid length
  let nonceData = iv.data()
  let nonce = try AES.GCM.Nonce(data: nonceData)

  guard let plaintextData = data.data(using: .utf8) else {
    throw WrongKeyUsageException()  //TOOO improve error handling
  }

  let encryptionResult = try AES.GCM.seal(
    plaintextData,
    using: key.getKey(),
    nonce: nonce)

  //TODO this should use  ciphertext but we need to return also TAG
  let cipherText = encryptionResult.combined

  guard let cipherText = encryptionResult.combined else {
    throw EncryptionFailedException("Incorrect AES configuration")
  }

  let base64cipherText = cipherText.base64EncodedString()
  return base64cipherText
}

private func decryptAesGcm(key: CryptoKey, data: String, iv: Uint8Array) throws -> String {
  guard key.keyUsages.contains(.encrypt) else {
    throw WrongKeyUsageException()
  }

  //TODO handle invalid length
  let nonceData = iv.data()
  let nonce = try AES.GCM.Nonce(data: nonceData)  // not needed but we need to migrate to using TAG

  guard let cipherData = Data(base64Encoded: data) else {
    throw WrongKeyUsageException()  // TODO: Improve error handling
  }

  let sealedBox = try AES.GCM.SealedBox(combined: cipherData)
  let plaintextData = try AES.GCM.open(sealedBox, using: key.getKey())

  guard let plaintext = String(data: plaintextData, encoding: .utf8) else {
    throw WrongKeyUsageException()  // TODO: Improve error handling
  }

  return plaintext
}

private func exportKey(format: KeyFormat, key: CryptoKey, dest: Uint8Array) throws {
  guard format == .raw else {
    throw WrongKeyUsageException()
  }

  //  TODO check for size
  key.getKey().withUnsafeBytes { bytes in
    let _ = bytes.copyBytes(to: dest.rawBufferPtr())
  }
}

private func importKey(format: KeyFormat, key: Uint8Array) throws -> CryptoKey {
  guard format == .raw else {
    throw WrongKeyUsageException()
  }

  let key = SymmetricKey(data: key.data())
  let cryptoKey = CryptoKey(
    algorithm: AesKeyGenParams(name: .gcm, length: 32), extractable: true,
    keyUsages: [.encrypt, .decrypt])
  cryptoKey.setKey(newKey: key)
  return cryptoKey
}



extension TypedArray {
  func data() -> Data {
    Data(bytes: self.rawPointer, count: self.byteLength)
  }

  func rawBufferPtr() -> UnsafeMutableRawBufferPointer {
    UnsafeMutableRawBufferPointer(
      start: self.rawPointer,
      count: self.byteLength)
  }
}

private class InvalidNonceException: Exception {
  override var reason: String {
    "Invalid nonce"
  }
}

private class WrongKeyUsageException: Exception {
  override var reason: String {
    "Wrong key usage"
  }
}

private class EncryptionFailedException: GenericException<String> {
  override var reason: String {
    "Failed to encrypt data: \(param)"
  }
}
private class LossyConversionException: Exception {
  override var reason: String {
    "Unable to convert given string without losing some information"
  }
}

private class FailedGeneratingRandomBytesException: GenericException<OSStatus> {
  override var reason: String {
    "Generating random bytes has failed with OSStatus code: \(param)"
  }
}
