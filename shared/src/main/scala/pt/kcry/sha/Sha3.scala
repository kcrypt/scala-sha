/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * Supported since 2022 by Kcrypt Lab UG <support@kcry.pt>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package pt.kcry.sha

/**
 * This implementation is based on https://keccak.team/keccak_specs_summary.html
 *
 * Keccak is quite universal and requires the sate which I kept inside an
 * object.
 */
class Keccak(private var len: Int) extends Hash {
  import java.lang.Long.rotateLeft

  private var length: Long = 0

  private val rate: Int = 200 - 2 * len

  private val S: Array[Long] = new Array[Long](25)

  def update(bytes: Array[Byte], off: Int, len: Int): Unit = {
    var i = 0
    while (i < len) {
      process(bytes(i + off).toInt)
      i += 1
    }
  }

  private def process(byt: Int): Unit = {
    var cnt = (length % rate).toInt
    val b = cnt % 8
    cnt /= 8
    val i = cnt % 5
    val j = cnt / 5

    S(i * 5 + j) ^= ((byt & 0xff).toLong << (8 * b))
    length += 1

    if ((length % rate) == 0) transform()
  }

  @inline
  private def transformRound(): Unit = {
    val C_0 = S(0) ^ S(1) ^ S(2) ^ S(3) ^ S(4)
    val C_1 = S(5) ^ S(6) ^ S(7) ^ S(8) ^ S(9)
    val C_2 = S(10) ^ S(11) ^ S(12) ^ S(13) ^ S(14)
    val C_3 = S(15) ^ S(16) ^ S(17) ^ S(18) ^ S(19)
    val C_4 = S(20) ^ S(21) ^ S(22) ^ S(23) ^ S(24)
    val D_0 = C_4 ^ rotateLeft(C_1, 1)
    val D_1 = C_0 ^ rotateLeft(C_2, 1)
    val D_2 = C_1 ^ rotateLeft(C_3, 1)
    val D_3 = C_2 ^ rotateLeft(C_4, 1)
    val D_4 = C_3 ^ rotateLeft(C_0, 1)
    val B_0_0 = S(0) ^ D_0
    val B_1_3 = rotateLeft(S(1) ^ D_0, 36)
    val B_2_1 = rotateLeft(S(2) ^ D_0, 3)
    val B_3_4 = rotateLeft(S(3) ^ D_0, 41)
    val B_4_2 = rotateLeft(S(4) ^ D_0, 18)
    val B_0_2 = rotateLeft(S(5) ^ D_1, 1)
    val B_1_0 = rotateLeft(S(6) ^ D_1, 44)
    val B_2_3 = rotateLeft(S(7) ^ D_1, 10)
    val B_3_1 = rotateLeft(S(8) ^ D_1, 45)
    val B_4_4 = rotateLeft(S(9) ^ D_1, 2)
    val B_0_4 = rotateLeft(S(10) ^ D_2, 62)
    val B_1_2 = rotateLeft(S(11) ^ D_2, 6)
    val B_2_0 = rotateLeft(S(12) ^ D_2, 43)
    val B_3_3 = rotateLeft(S(13) ^ D_2, 15)
    val B_4_1 = rotateLeft(S(14) ^ D_2, 61)
    val B_0_1 = rotateLeft(S(15) ^ D_3, 28)
    val B_1_4 = rotateLeft(S(16) ^ D_3, 55)
    val B_2_2 = rotateLeft(S(17) ^ D_3, 25)
    val B_3_0 = rotateLeft(S(18) ^ D_3, 21)
    val B_4_3 = rotateLeft(S(19) ^ D_3, 56)
    val B_0_3 = rotateLeft(S(20) ^ D_4, 27)
    val B_1_1 = rotateLeft(S(21) ^ D_4, 20)
    val B_2_4 = rotateLeft(S(22) ^ D_4, 39)
    val B_3_2 = rotateLeft(S(23) ^ D_4, 8)
    val B_4_0 = rotateLeft(S(24) ^ D_4, 14)
    S(0) = B_0_0 ^ (~B_1_0 & B_2_0)
    S(1) = B_0_1 ^ (~B_1_1 & B_2_1)
    S(2) = B_0_2 ^ (~B_1_2 & B_2_2)
    S(3) = B_0_3 ^ (~B_1_3 & B_2_3)
    S(4) = B_0_4 ^ (~B_1_4 & B_2_4)
    S(5) = B_1_0 ^ (~B_2_0 & B_3_0)
    S(6) = B_1_1 ^ (~B_2_1 & B_3_1)
    S(7) = B_1_2 ^ (~B_2_2 & B_3_2)
    S(8) = B_1_3 ^ (~B_2_3 & B_3_3)
    S(9) = B_1_4 ^ (~B_2_4 & B_3_4)
    S(10) = B_2_0 ^ (~B_3_0 & B_4_0)
    S(11) = B_2_1 ^ (~B_3_1 & B_4_1)
    S(12) = B_2_2 ^ (~B_3_2 & B_4_2)
    S(13) = B_2_3 ^ (~B_3_3 & B_4_3)
    S(14) = B_2_4 ^ (~B_3_4 & B_4_4)
    S(15) = B_3_0 ^ (~B_4_0 & B_0_0)
    S(16) = B_3_1 ^ (~B_4_1 & B_0_1)
    S(17) = B_3_2 ^ (~B_4_2 & B_0_2)
    S(18) = B_3_3 ^ (~B_4_3 & B_0_3)
    S(19) = B_3_4 ^ (~B_4_4 & B_0_4)
    S(20) = B_4_0 ^ (~B_0_0 & B_1_0)
    S(21) = B_4_1 ^ (~B_0_1 & B_1_1)
    S(22) = B_4_2 ^ (~B_0_2 & B_1_2)
    S(23) = B_4_3 ^ (~B_0_3 & B_1_3)
    S(24) = B_4_4 ^ (~B_0_4 & B_1_4)
  }

  private def transform(): Unit = {
    transformRound()
    S(0) ^= 0x0000000000000001L
    transformRound()
    S(0) ^= 0x0000000000008082L
    transformRound()
    S(0) ^= 0x800000000000808aL
    transformRound()
    S(0) ^= 0x8000000080008000L
    transformRound()
    S(0) ^= 0x000000000000808bL
    transformRound()
    S(0) ^= 0x0000000080000001L
    transformRound()
    S(0) ^= 0x8000000080008081L
    transformRound()
    S(0) ^= 0x8000000000008009L
    transformRound()
    S(0) ^= 0x000000000000008aL
    transformRound()
    S(0) ^= 0x0000000000000088L
    transformRound()
    S(0) ^= 0x0000000080008009L
    transformRound()
    S(0) ^= 0x000000008000000aL
    transformRound()
    S(0) ^= 0x000000008000808bL
    transformRound()
    S(0) ^= 0x800000000000008bL
    transformRound()
    S(0) ^= 0x8000000000008089L
    transformRound()
    S(0) ^= 0x8000000000008003L
    transformRound()
    S(0) ^= 0x8000000000008002L
    transformRound()
    S(0) ^= 0x8000000000000080L
    transformRound()
    S(0) ^= 0x000000000000800aL
    transformRound()
    S(0) ^= 0x800000008000000aL
    transformRound()
    S(0) ^= 0x8000000080008081L
    transformRound()
    S(0) ^= 0x8000000000008080L
    transformRound()
    S(0) ^= 0x0000000080000001L
    transformRound()
    S(0) ^= 0x8000000080008008L
  }

  def finish(hashed: Array[Byte], off: Int): Unit =
    squeeze(mask = 0x06, hashed = hashed, off = off, len = len)

  def finish(hashed: Array[Byte], off: Int, len: Int): Unit =
    squeeze(mask = 0x1f, hashed = hashed, off = off, len = len)

  def squeeze(mask: Int, hashed: Array[Byte], off: Int, len: Int): Unit = {
    val q: Int = rate - (length % rate).toInt
    if (q == 1) process(0x80 + mask)
    else {
      process(mask)
      while (length % rate != rate - 1) process(0x00)
      process(0x80)
    }
    squeeze(hashed = hashed, off = off, len = len)
  }

  def squeeze(hashed: Array[Byte], off: Int, len: Int): Unit = {
    var done = false
    var i = 0
    var j = 0
    var k = 0
    var m = 0

    while (!done) {
      j = 0
      while (j < 5 && !done) {
        i = 0
        while (i < 5 && !done) {
          var el = S(i * 5 + j)
          k = 0
          while (k < 8 && !done) {
            hashed(m + off) = (el & 0xff).toByte
            m += 1
            if (m >= len || (m % rate) == 0) done = true
            el >>>= 8
            k += 1
          }
          i += 1
        }
        j += 1
      }

      if (m < len) done = false

      transform()
    }
  }
}

sealed trait Sha3 {
  val HASH_SIZE: Int

  def hash(message: Array[Byte]): Array[Byte] = {
    val keccak = new Keccak(HASH_SIZE)
    keccak.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    keccak.finish(hashed, 0)
    hashed
  }
}

sealed trait Shake {
  val HASH_SIZE: Int

  def hash(message: Array[Byte], outputLen: Int): Array[Byte] = {
    val keccak = new Keccak(HASH_SIZE)
    keccak.update(message, 0, message.length)
    val hashed = new Array[Byte](outputLen)
    keccak.finish(hashed, 0, outputLen)
    hashed
  }
}

class Sha3_224 extends Keccak(Sha3_224.HASH_SIZE)

object Sha3_224 extends Sha3 {
  val HASH_SIZE: Int = 28
}

class Sha3_256 extends Keccak(Sha3_256.HASH_SIZE)

object Sha3_256 extends Sha3 {
  val HASH_SIZE: Int = 32
}

class Sha3_384 extends Keccak(Sha3_384.HASH_SIZE)

object Sha3_384 extends Sha3 {
  val HASH_SIZE: Int = 48
}

class Sha3_512 extends Keccak(Sha3_512.HASH_SIZE)

object Sha3_512 extends Sha3 {
  val HASH_SIZE: Int = 64
}

class Shake_128 extends Keccak(Shake_128.HASH_SIZE)

object Shake_128 extends Shake {
  val HASH_SIZE: Int = 16
}

class Shake_256 extends Keccak(Shake_256.HASH_SIZE)

object Shake_256 extends Shake {
  val HASH_SIZE: Int = 32
}
