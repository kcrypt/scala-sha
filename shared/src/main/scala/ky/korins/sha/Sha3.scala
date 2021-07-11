/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package ky.korins.sha

/**
 * This implementation is based on https://keccak.team/keccak_specs_summary.html
 *
 * Keccak is quite universal and requires the sate which I kept inside an object.
 */
class Keccak(private var len: Int) {
  import Keccak._
  import java.lang.Long.rotateLeft

  private var length: Long = 0

  private val rate: Int = 200 - 2 * len

  private val S: Array[Array[Long]] = Array.ofDim[Long](5, 5)

  def process(bytes: Array[Byte]): Unit = {
    var i = 0
    while (i < bytes.length) {
      process(bytes(i).toInt)
      i += 1
    }
  }

  private def process(byt: Int): Unit = {
    var cnt = (length % rate).toInt
    val b = cnt % 8
    cnt /= 8
    val i = cnt % 5
    val j = cnt / 5

    S(i)(j) ^= ((byt & 0xff).toLong << (8 * b))
    length += 1

    if ((length % rate) == 0) {
      transform()
    }
  }

  private def transform(): Unit = {
    val C = new Array[Long](5)
    val D = new Array[Long](5)
    val B = Array.ofDim[Long](5, 5)
    var k = 0
    while (k < 24) {
      C(0) = S(0)(0) ^ S(0)(1) ^ S(0)(2) ^ S(0)(3) ^ S(0)(4)
      C(1) = S(1)(0) ^ S(1)(1) ^ S(1)(2) ^ S(1)(3) ^ S(1)(4)
      C(2) = S(2)(0) ^ S(2)(1) ^ S(2)(2) ^ S(2)(3) ^ S(2)(4)
      C(3) = S(3)(0) ^ S(3)(1) ^ S(3)(2) ^ S(3)(3) ^ S(3)(4)
      C(4) = S(4)(0) ^ S(4)(1) ^ S(4)(2) ^ S(4)(3) ^ S(4)(4)
      D(0) = C(4) ^ rotateLeft(C(1), 1)
      D(1) = C(0) ^ rotateLeft(C(2), 1)
      D(2) = C(1) ^ rotateLeft(C(3), 1)
      D(3) = C(2) ^ rotateLeft(C(4), 1)
      D(4) = C(3) ^ rotateLeft(C(0), 1)
      var i = 0
      while (i < 5) {
        var j = 0
        while (j < 5) {
          S(i)(j) ^= D(i)
          j += 1
        }
        i += 1
      }
      B(0)(0) = S(0)(0)
      B(1)(3) = rotateLeft(S(0)(1), 36)
      B(2)(1) = rotateLeft(S(0)(2), 3)
      B(3)(4) = rotateLeft(S(0)(3), 41)
      B(4)(2) = rotateLeft(S(0)(4), 18)
      B(0)(2) = rotateLeft(S(1)(0), 1)
      B(1)(0) = rotateLeft(S(1)(1), 44)
      B(2)(3) = rotateLeft(S(1)(2), 10)
      B(3)(1) = rotateLeft(S(1)(3), 45)
      B(4)(4) = rotateLeft(S(1)(4), 2)
      B(0)(4) = rotateLeft(S(2)(0), 62)
      B(1)(2) = rotateLeft(S(2)(1), 6)
      B(2)(0) = rotateLeft(S(2)(2), 43)
      B(3)(3) = rotateLeft(S(2)(3), 15)
      B(4)(1) = rotateLeft(S(2)(4), 61)
      B(0)(1) = rotateLeft(S(3)(0), 28)
      B(1)(4) = rotateLeft(S(3)(1), 55)
      B(2)(2) = rotateLeft(S(3)(2), 25)
      B(3)(0) = rotateLeft(S(3)(3), 21)
      B(4)(3) = rotateLeft(S(3)(4), 56)
      B(0)(3) = rotateLeft(S(4)(0), 27)
      B(1)(1) = rotateLeft(S(4)(1), 20)
      B(2)(4) = rotateLeft(S(4)(2), 39)
      B(3)(2) = rotateLeft(S(4)(3), 8)
      B(4)(0) = rotateLeft(S(4)(4), 14)
      i = 0
      while (i < 5) {
        var j = 0
        while (j < 5) {
          S(i)(j) = B(i)(j) ^ (~B((i + 1) % 5)(j) & B((i + 2) % 5)(j))
          j += 1
        }
        i += 1
      }
      S(0)(0) ^= RC(k)
      k += 1
    }
  }

  def hash(): Array[Byte] =
    squeeze(mask = 0x06, len = len)

  def shake(outputLen: Int): Array[Byte] =
    squeeze(mask = 0x1f, len = outputLen)

  private def squeeze(mask: Int, len: Int): Array[Byte] = {
    val q: Int = rate - (length % rate).toInt
    if (q == 1) {
      process(0x80 + mask)
    } else {
      process(mask)
      while (length % rate != rate - 1) {
        process(0x00)
      }
      process(0x80)
    }

    val buff = new Array[Byte](len)
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
          var el = S(i)(j)
          k = 0
          while (k < 8 && !done) {
            buff(m) = (el & 0xff).toByte
            m += 1
            if (m >= len || (m % rate) == 0) {
              done = true
            }
            el >>>= 8
            k += 1
          }
          i += 1
        }
        j += 1
      }

      if (m < len) {
        done = false
      }

      transform()
    }
    buff
  }
}

private[sha] object Keccak {
  val RC: Array[Long] = Array(
    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
    0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
    0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
    0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
    0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
    0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
    0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
    0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
  )
}

object Sha3_224 {
  def hash(message: Array[Byte]): Array[Byte] = {
    val keccak = new Keccak(28)
    keccak.process(message)
    keccak.hash()
  }
}

object Sha3_256 {
  def hash(message: Array[Byte]): Array[Byte] = {
    val keccak = new Keccak(32)
    keccak.process(message)
    keccak.hash()
  }
}

object Sha3_384 {
  def hash(message: Array[Byte]): Array[Byte] = {
    val keccak = new Keccak(48)
    keccak.process(message)
    keccak.hash()
  }
}

object Sha3_512 {
  def hash(message: Array[Byte]): Array[Byte] = {
    val keccak = new Keccak(64)
    keccak.process(message)
    keccak.hash()
  }
}

object Shake_128 {
  def hash(message: Array[Byte], outputLen: Int): Array[Byte] = {
    val keccak = new Keccak(16)
    keccak.process(message)
    keccak.shake(outputLen)
  }
}

object Shake_256 {
  def hash(message: Array[Byte], outputLen: Int): Array[Byte] = {
    val keccak = new Keccak(32)
    keccak.process(message)
    keccak.shake(outputLen)
  }
}
