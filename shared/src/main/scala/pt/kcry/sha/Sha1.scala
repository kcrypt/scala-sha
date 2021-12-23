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
 * Quite ugly but fast enough implementation of SHA-1.
 *
 * This implementation isn't thread safe.
 */
class Sha1() extends BlockedHash[Array[Int]] {
  import java.lang.Integer.rotateLeft

  private var H0 = 0x67452301
  private var H1 = 0xefcdab89
  private var H2 = 0x98badcfe
  private var H3 = 0x10325476
  private var H4 = 0xc3d2e1f0

  protected val words = new Array[Int](80)
  protected val block = new Array[Byte](64)

  // the only reason to keep it as function is easy way to implement SHA-0 :)
  protected def processBlockWord(j: Int): Int =
    rotateLeft(words(j - 3) ^ words(j - 8) ^ words(j - 14) ^ words(j - 16), 1)

  protected def finishBlock(block: Array[Byte], off: Int): Unit = {
    var j = 0
    while (j < 16) {
      words(j) = 0
      var k = 0
      while (k < 4) {
        words(j) |= ((block(j * 4 + k + off) & 0x000000ff) << (24 - k * 8))
        k += 1
      }
      j += 1
    }

    while (j < 80) {
      words(j) = processBlockWord(j)
      j += 1
    }

    var A = H0
    var B = H1
    var C = H2
    var D = H3
    var E = H4
    var F = 0
    var G = 0
    j = 0
    while (j < 80) {
      if (j < 20) {
        F = (B & C) | (~B & D)
        G = 0x5a827999
      } else if (19 < j && j < 40) {
        F = B ^ C ^ D
        G = 0x6ed9eba1
      } else if (39 < j && j < 60) {
        F = (B & C) | (B & D) | (C & D)
        G = 0x8f1bbcdc
      } else {
        F = B ^ C ^ D
        G = 0xca62c1d6
      }

      val temp = rotateLeft(A, 5) + F + E + G + words(j)

      E = D
      D = C
      C = rotateLeft(B, 30)
      B = A
      A = temp
      j += 1
    }

    H0 += A
    H1 += B
    H2 += C
    H3 += D
    H4 += E
  }

  def finish(hashed: Array[Byte], off: Int): Unit = {
    val padded = padding_32bit(messageLen)
    update(padded, 0, padded.length)

    hashed(0 + off) = ((H0 >>> 24) & 0xff).toByte
    hashed(1 + off) = ((H0 >>> 16) & 0xff).toByte
    hashed(2 + off) = ((H0 >>> 8) & 0xff).toByte
    hashed(3 + off) = (H0 & 0xff).toByte
    hashed(4 + off) = ((H1 >>> 24) & 0xff).toByte
    hashed(5 + off) = ((H1 >>> 16) & 0xff).toByte
    hashed(6 + off) = ((H1 >>> 8) & 0xff).toByte
    hashed(7 + off) = (H1 & 0xff).toByte
    hashed(8 + off) = ((H2 >>> 24) & 0xff).toByte
    hashed(9 + off) = ((H2 >>> 16) & 0xff).toByte
    hashed(10 + off) = ((H2 >>> 8) & 0xff).toByte
    hashed(11 + off) = (H2 & 0xff).toByte
    hashed(12 + off) = ((H3 >>> 24) & 0xff).toByte
    hashed(13 + off) = ((H3 >>> 16) & 0xff).toByte
    hashed(14 + off) = ((H3 >>> 8) & 0xff).toByte
    hashed(15 + off) = (H3 & 0xff).toByte
    hashed(16 + off) = ((H4 >>> 24) & 0xff).toByte
    hashed(17 + off) = ((H4 >>> 16) & 0xff).toByte
    hashed(18 + off) = ((H4 >>> 8) & 0xff).toByte
    hashed(19 + off) = (H4 & 0xff).toByte
  }
}

object Sha1 {
  val HASH_SIZE: Int = 20

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha1 = new Sha1()
    sha1.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha1.finish(hashed, 0)
    hashed
  }
}
