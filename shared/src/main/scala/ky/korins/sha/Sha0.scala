/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package ky.korins.sha

/**
 * Quite ugly but fast enough implementation of SHA-0
 *
 * Keep in mind that SHA-0 is broken and I implemented it just for fun :)
 */
object Sha0 {
  def hash(message: Array[Byte]): Array[Byte] = {
    import java.lang.Integer.rotateLeft

    var H0 = 0x67452301
    var H1 = 0xefcdab89
    var H2 = 0x98badcfe
    var H3 = 0x10325476
    var H4 = 0xc3d2e1f0

    val words = new Array[Int](80)
    val block = new Array[Byte](64)
    var padded = new Array[Byte](message.length + 64 - (message.length % 64))
    val hashed = new Array[Byte](20)

    padded = Paddings.padding_32(message)
    val blocks = padded.length / 64

    var i = 0
    while (i < blocks) {
      System.arraycopy(padded, 64 * i, block, 0, 64)
      var j = 0
      while (j < 16) {
        words(j) = 0
        var k = 0
        while (k < 4) {
          words(j) |= ((block(j * 4 + k) & 0x000000ff) << (24 - k * 8))
          k += 1
        }
        j += 1
      }

      while (j < 80) {
        words(j) = words(j - 3) ^ words(j - 8) ^ words(j - 14) ^ words(j - 16)
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
      i += 1
    }

    hashed(0) = ((H0 >>> 24) & 0xff).toByte
    hashed(1) = ((H0 >>> 16) & 0xff).toByte
    hashed(2) = ((H0 >>> 8) & 0xff).toByte
    hashed(3) = (H0 & 0xff).toByte
    hashed(4) = ((H1 >>> 24) & 0xff).toByte
    hashed(5) = ((H1 >>> 16) & 0xff).toByte
    hashed(6) = ((H1 >>> 8) & 0xff).toByte
    hashed(7) = (H1 & 0xff).toByte
    hashed(8) = ((H2 >>> 24) & 0xff).toByte
    hashed(9) = ((H2 >>> 16) & 0xff).toByte
    hashed(10) = ((H2 >>> 8) & 0xff).toByte
    hashed(11) = (H2 & 0xff).toByte
    hashed(12) = ((H3 >>> 24) & 0xff).toByte
    hashed(13) = ((H3 >>> 16) & 0xff).toByte
    hashed(14) = ((H3 >>> 8) & 0xff).toByte
    hashed(15) = (H3 & 0xff).toByte
    hashed(16) = ((H4 >>> 24) & 0xff).toByte
    hashed(17) = ((H4 >>> 16) & 0xff).toByte
    hashed(18) = ((H4 >>> 8) & 0xff).toByte
    hashed(19) = (H4 & 0xff).toByte

    hashed
  }
}
