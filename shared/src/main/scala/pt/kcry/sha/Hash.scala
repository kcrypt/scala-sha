/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * Supported since 2022 by Kcrypt Lab UG <opensource@kcry.pt>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package pt.kcry.sha

trait Hash {
  def update(bytes: Array[Byte], off: Int, len: Int): Unit

  def finish(hashed: Array[Byte], off: Int): Unit

  def finish(hashed: Array[Byte], off: Int, len: Int): Unit
}

private[sha] trait BlockedHash[T <: Array[_]] extends Hash {

  protected val words: T
  protected val block: Array[Byte]
  private var blockPos = 0

  protected var messageLen = 0

  protected def finishBlock(block: Array[Byte], off: Int): Unit

  def update(bytes: Array[Byte], off: Int, len: Int): Unit = {
    var rem = len
    var pos = off
    if (blockPos > 0) {
      val use = math.min(block.length - blockPos, rem)
      System.arraycopy(bytes, pos, block, blockPos, use)
      rem -= use
      pos += use
      blockPos += use
    }
    if (blockPos == block.length) {
      finishBlock(block, 0)
      blockPos = 0
    }
    while (rem >= block.length) {
      finishBlock(bytes, pos)
      pos += block.length
      rem -= block.length
    }
    if (rem > 0) {
      System.arraycopy(bytes, pos, block, 0, rem)
      blockPos = rem
    }
    messageLen += len
  }

  final def finish(hashed: Array[Byte], off: Int, len: Int): Unit =
    throw new NotImplementedError("XOF doesn't defined")

  protected def padding_32bit(messageLen: Int): Array[Byte] = {
    val tailLength = messageLen & 0x3f
    val padLength = if (tailLength < 56) 64 - tailLength else 128 - tailLength

    val padded = new Array[Byte](padLength)
    padded(0) = 0x80.toByte

    val lengthInBits = messageLen.toLong * 8
    var i = 0
    while (i < 8) {
      padded(padded.length - 1 - i) = ((lengthInBits >>> (8 * i)) & 0xff).toByte
      i += 1
    }

    padded
  }

  protected def padding_64bit(messageLen: Int): Array[Byte] = {
    val tailLength = messageLen & 0x7f
    val padLength = if (tailLength < 112) 128 - tailLength else 256 - tailLength

    val padded = new Array[Byte](padLength)
    padded(0) = 0x80.toByte

    val lengthInBits = messageLen.toLong * 8
    var i = 0
    while (i < 8) {
      padded(padded.length - 1 - i) = ((lengthInBits >>> (8 * i)) & 0xff).toByte
      i += 1
    }

    padded
  }
}
