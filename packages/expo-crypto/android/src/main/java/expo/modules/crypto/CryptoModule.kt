package expo.modules.crypto

import android.util.Base64
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.typedarray.TypedArray
import expo.modules.kotlin.typedarray.Uint8Array
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoModule : Module() {
  private val secureRandom by lazy { SecureRandom() }

  override fun definition() = ModuleDefinition {
    Name("ExpoCrypto")

    Class("AesGcmParams")

    Class(CryptoKey::class) {
      Constructor { algorithm:AesKeyGenParams, extractable: Boolean, keyUsages: List<KeyUsage> ->
        return@Constructor CryptoKey(algorithm, extractable, keyUsages)
      }
    }

    Function("digestString", this@CryptoModule::digestString)
    AsyncFunction("digestStringAsync", this@CryptoModule::digestString)
    Function("getRandomBase64String", this@CryptoModule::getRandomBase64String)
    AsyncFunction("getRandomBase64StringAsync", this@CryptoModule::getRandomBase64String)
    Function("getRandomValues", this@CryptoModule::getRandomValues)
    Function("digest", this@CryptoModule::digest)
    Function("randomUUID") {
      UUID.randomUUID().toString()
    }
    Function("encryptAesGcm", this@CryptoModule::encryptAesGcm)
    Function("decryptAesGcm", this@CryptoModule::decryptAesGcm)
    Function("exportKey", this@CryptoModule::exportKey)
    Function("importKey", this@CryptoModule::importKey)
  }

  private fun getRandomBase64String(randomByteCount: Int): String {
    val output = ByteArray(randomByteCount)
    secureRandom.nextBytes(output)
    return Base64.encodeToString(output, Base64.NO_WRAP)
  }

  private fun digestString(algorithm: DigestAlgorithm, data: String, options: DigestOptions): String {
    val messageDigest = MessageDigest.getInstance(algorithm.value).apply { update(data.toByteArray()) }

    val digest: ByteArray = messageDigest.digest()
    return when (options.encoding) {
      DigestOptions.Encoding.BASE64 -> {
        Base64.encodeToString(digest, Base64.NO_WRAP)
      }
      DigestOptions.Encoding.HEX -> {
        digest.joinToString(separator = "") { byte ->
          ((byte.toInt() and 0xff) + 0x100)
            .toString(radix = 16)
            .substring(startIndex = 1)
        }
      }
    }
  }

  private fun digest(algorithm: DigestAlgorithm, output: TypedArray, data: TypedArray) {
    val messageDigest = MessageDigest.getInstance(algorithm.value).apply { update(data.toDirectBuffer()) }

    val digest: ByteArray = messageDigest.digest()
    output.write(digest, output.byteOffset, output.byteLength)
  }

  private fun getRandomValues(typedArray: TypedArray) {
    val array = ByteArray(typedArray.byteLength)
    secureRandom.nextBytes(array)
    typedArray.write(array, typedArray.byteOffset, typedArray.byteLength)
  }

  private fun encryptAesGcm(key: CryptoKey, data: String, iv: Uint8Array): String {
    if(!key.keyUsages.contains(KeyUsage.ENCRYPT)) {
      throw WrongKeyUsageException();
    }

    val dataBytes = data.toByteArray();

    val ivBuffer = iv.toDirectBuffer();
    val ivBytes = ByteArray(iv.length).also (ivBuffer::get)

    val spec = GCMParameterSpec(128, ivBytes)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(key.getKey().encoded,"AES")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec)

    val cipherText = cipher.doFinal(dataBytes)

    return Base64.encodeToString(cipherText, Base64.DEFAULT)
  }

  private fun decryptAesGcm(key: CryptoKey, data: String, iv: Uint8Array): String {
    if(!key.keyUsages.contains(KeyUsage.DECRYPT)) {
      throw WrongKeyUsageException();
    }

    val ivBuffer = iv.toDirectBuffer();
    val ivBytes = ByteArray(iv.length).also(ivBuffer::get)

    val spec = GCMParameterSpec(128, ivBytes)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(key.getKey().encoded,"AES")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, spec)

    val decoded = Base64.decode(data, Base64.DEFAULT)

    val plaintext = cipher.doFinal(decoded)

    return String(plaintext, Charset.forName("UTF-8"))
  }

  private fun exportKey(format: KeyFormat, key: CryptoKey, dest: Uint8Array) {
    if(format != KeyFormat.RAW) {
      throw WrongKeyUsageException();
    }

    //  TODO check for size
    val keyBytes = key.getKey().encoded
    dest.write(keyBytes, position = 0, size = keyBytes.size)
  }

  private fun importKey(format: KeyFormat, key: Uint8Array, cryptoKey: CryptoKey) {
    if(format != KeyFormat.RAW) {
      throw WrongKeyUsageException();
    }

    //  TODO check for size
    val secKey = key.toSecretKey()
    cryptoKey.setKey(secKey)
  }
}

fun ByteArray.toSecretKey(algorithm: String = "AES") =
  SecretKeySpec(this, 0, this.size, algorithm)

fun Uint8Array.toSecretKey(): SecretKey {
  return ByteArray(32)
    .also { bytes -> this.read(bytes, 0, 32) }
    .toSecretKey()
}

class WrongKeyUsageException : CodedException(
  message = "Wrong key usage"
)

class InvalidKeyAlgorithm : CodedException(
  message = "Invalid key Algorithm"
)
