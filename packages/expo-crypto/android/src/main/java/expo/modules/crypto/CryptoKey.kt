package expo.modules.crypto

import expo.modules.kotlin.apifeatures.EitherType
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import expo.modules.kotlin.records.Required
import expo.modules.kotlin.sharedobjects.SharedObject
import expo.modules.kotlin.types.Enumerable
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


enum class KeyUsage(val value: String) : Enumerable {
  ENCRYPT("encrypt"),
  DECRYPT("decrypt"),
  SIGN("sign"),
  VERIFY("verify"),
  DERIVEKEY("deriveKey"),
  DERIVEBITS("deriveBits"),
  WRAPKEY("wrapKey"),
  UNWRAPKEY("unwrapKey")
}

class AesKeyGenParams : Record {
  @Field
  @Required
  val name: AlgorithmName = AlgorithmName.GCM

  @Field
  @Required
  val length: Int = 32

  enum class AlgorithmName(val value: String) : Enumerable {
    CBC("AES-CBC"),
    GCM("AES-GCM")
  }
}

class HmacKeyGenParams : Record {
  @Field
  @Required
  val name: AlgorithmName = AlgorithmName.HMAC

  enum class AlgorithmName(val value: String) : Enumerable {
    HMAC("HMAC"),
  }
}

class CryptoKey(
  private var _algorithm: AesKeyGenParams,
  private var _extractable: Boolean,
  private val _keyUsages: List<KeyUsage>) : SharedObject() {

  private val algorithm get() = _algorithm
  private val extractable get() = _extractable
  val keyUsages get() = _keyUsages

  private val secureRandom by lazy { SecureRandom() }
  private lateinit var secretKey: SecretKey
  init {
    when(algorithm.name) {
      AesKeyGenParams.AlgorithmName.GCM -> {
        val keygen = KeyGenerator.getInstance("AES").apply {
          init(256, secureRandom)
        }
        secretKey = keygen.generateKey();
      }
      else -> {
        println("Algorithm is of an unknown type")
      }
    }
  }

  fun getKey(): SecretKey {
    return secretKey
  }
}
