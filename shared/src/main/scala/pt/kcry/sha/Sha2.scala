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
 * Quite ugly but fast enough implementation of SHA-2 for 32 bit case.
 *
 * This implementation isn't thread safe.
 */
sealed trait Sha2_32bit extends BlockedHash[Array[Int]] {
  import Sha2._

  import java.lang.Integer.rotateRight

  protected val H: Array[Int]

  protected val len: Int

  protected val words = new Array[Int](64)
  protected val block = new Array[Byte](64)

  override def finish(hashed: Array[Byte], off: Int): Unit = {
    val padded = padding_32bit(messageLen)
    update(padded, 0, padded.length)

    var i = 0
    while (i < len) {
      val c = 4 * i
      hashed(c + off) = ((H(i) >>> 56) & 0xff).toByte
      hashed(c + 1 + off) = ((H(i) >>> (56 - 8)) & 0xff).toByte
      hashed(c + 2 + off) = ((H(i) >>> (56 - 16)) & 0xff).toByte
      hashed(c + 3 + off) = ((H(i) >>> (56 - 24)) & 0xff).toByte
      i += 1
    }
  }

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

    while (j < 64) {
      val s0 = rotateRight(words(j - 15), 7) ^
        rotateRight(words(j - 15), 18) ^ (words(j - 15) >>> 3)
      val s1 =
        rotateRight(words(j - 2), 17) ^
          rotateRight(words(j - 2), 19) ^ (words(j - 2) >>> 10)
      words(j) = words(j - 16) + s0 + words(j - 7) + s1
      j += 1
    }

    var a = H(0)
    var b = H(1)
    var c = H(2)
    var d = H(3)
    var e = H(4)
    var f = H(5)
    var g = H(6)
    var h = H(7)
    j = 0
    while (j < 64) {
      val s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
      val maj = (a & b) ^ (a & c) ^ (b & c)
      val t2 = s0 + maj
      val s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
      val ch = (e & f) ^ (~e & g)
      val t1 = h + s1 + ch + K_32bit(j) + words(j)
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
      j += 1
    }

    H(0) += a
    H(1) += b
    H(2) += c
    H(3) += d
    H(4) += e
    H(5) += f
    H(6) += g
    H(7) += h
  }
}

/**
 * Quite ugly but fast enough implementation of SHA-2 for 64 bit case.
 *
 * This implementation isn't thread safe.
 */
sealed trait Sha2_64bit extends BlockedHash[Array[Long]] {
  import Sha2._

  import java.lang.Long.rotateRight

  protected val H: Array[Long]

  protected val len: Int

  protected val words = new Array[Long](80)
  protected val block = new Array[Byte](128)

  override def finish(hashed: Array[Byte], off: Int): Unit = {
    val padded = padding_64bit(messageLen)
    update(padded, 0, padded.length)

    var i = 0
    while (i < len) {
      val c = 8 * i
      hashed(c + off) = ((H(i) >>> 56) & 0xff).toByte
      hashed(c + 1 + off) = ((H(i) >>> (56 - 8)) & 0xff).toByte
      hashed(c + 2 + off) = ((H(i) >>> (56 - 16)) & 0xff).toByte
      hashed(c + 3 + off) = ((H(i) >>> (56 - 24)) & 0xff).toByte
      hashed(c + 4 + off) = ((H(i) >>> (56 - 32)) & 0xff).toByte
      hashed(c + 5 + off) = ((H(i) >>> (56 - 40)) & 0xff).toByte
      hashed(c + 6 + off) = ((H(i) >>> (56 - 48)) & 0xff).toByte
      hashed(c + 7 + off) = (H(i) & 0xff).toByte
      i += 1
    }
  }

  protected def finishBlock(block: Array[Byte], off: Int): Unit = {
    var j = 0
    while (j < 16) {
      words(j) = 0
      var k = 0
      while (k < 8) {
        words(j) |= ((block(
          j * 8 + k + off
        ) & 0x00000000000000ffL) << (56 - k * 8))
        k += 1
      }
      j += 1
    }

    while (j < 80) {
      val s0 =
        rotateRight(words(j - 15), 1) ^
          rotateRight(words(j - 15), 8) ^ (words(j - 15) >>> 7)
      val s1 =
        rotateRight(words(j - 2), 19) ^
          rotateRight(words(j - 2), 61) ^ (words(j - 2) >>> 6)
      words(j) = words(j - 16) + s0 + words(j - 7) + s1
      j += 1
    }

    var a = H(0)
    var b = H(1)
    var c = H(2)
    var d = H(3)
    var e = H(4)
    var f = H(5)
    var g = H(6)
    var h = H(7)
    j = 0
    while (j < 80) {
      val s0 = rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39)
      val maj = (a & b) ^ (a & c) ^ (b & c)
      val t2 = s0 + maj
      val s1 = rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41)
      val ch = (e & f) ^ (~e & g)
      val t1 = h + s1 + ch + K_64bit(j) + words(j)
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
      j += 1
    }

    H(0) += a
    H(1) += b
    H(2) += c
    H(3) += d
    H(4) += e
    H(5) += f
    H(6) += g
    H(7) += h
  }
}

private[sha] object Sha2 {
  val K_32bit: Array[Int] = Array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  )

  val K_64bit: Array[Long] = Array(
    0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
    0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L,
    0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L,
    0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
    0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
    0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
    0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L,
    0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
    0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
    0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
    0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
    0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
    0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
    0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
    0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
    0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
    0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
    0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
    0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL,
    0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
    0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
    0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L,
    0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL,
    0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
    0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
    0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
    0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
  )

}

class Sha2_224 extends Sha2_32bit {
  override protected val H: Array[Int] = Array(
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
    0x64f98fa7, 0xbefa4fa4
  )

  override protected val len: Int = 7
}

object Sha2_224 {
  val HASH_SIZE: Int = 28

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha2_224 = new Sha2_224()
    sha2_224.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha2_224.finish(hashed, 0)
    hashed
  }
}

class Sha2_256 extends Sha2_32bit {
  override protected val H: Array[Int] = Array(
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  )

  override protected val len: Int = 8
}

object Sha2_256 {
  val HASH_SIZE: Int = 32

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha2_256 = new Sha2_256()
    sha2_256.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha2_256.finish(hashed, 0)
    hashed
  }
}

class Sha2_384 extends Sha2_64bit {
  override protected val H: Array[Long] = Array(
    0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L,
    0x152fecd8f70e5939L, 0x67332667ffc00b31L, 0x8eb44a8768581511L,
    0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L
  )

  override protected val len: Int = 6
}

object Sha2_384 {
  val HASH_SIZE: Int = 48

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha2_384 = new Sha2_384()
    sha2_384.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha2_384.finish(hashed, 0)
    hashed
  }
}

class Sha2_512 extends Sha2_64bit {
  override protected val H: Array[Long] = Array(
    0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
    0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
    0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
  )

  override protected val len: Int = 8
}

object Sha2_512 {
  val HASH_SIZE: Int = 64

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha2_512 = new Sha2_512()
    sha2_512.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha2_512.finish(hashed, 0)
    hashed
  }
}
