/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package ky.korins.sha

/**
 * Keep in mind that SHA-0 is broken and I implemented it just for fun :)
 *
 * This implementation also isn't thread safe.
 */
class Sha0 extends Sha1 {
  override protected def processBlockWord(j: Int): Int =
    words(j - 3) ^ words(j - 8) ^ words(j - 14) ^ words(j - 16)
}

object Sha0 {
  val HASH_SIZE: Int = Sha1.HASH_SIZE

  def hash(message: Array[Byte]): Array[Byte] = {
    val sha0 = new Sha0()
    sha0.update(message, 0, message.length)
    val hashed = new Array[Byte](HASH_SIZE)
    sha0.finish(hashed, 0)
    hashed
  }
}
