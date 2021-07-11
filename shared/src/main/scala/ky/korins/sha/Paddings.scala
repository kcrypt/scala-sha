/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package ky.korins.sha

private[sha] object Paddings {
  def padding_32(message: Array[Byte]): Array[Byte] = {
    val origLength = message.length
    val tailLength = origLength & 0x3f
    val padLength = if (tailLength < 56) 64 - tailLength else 128 - tailLength

    val thePad = new Array[Byte](padLength)
    thePad(0) = 0x80.toByte

    val lengthInBits = origLength.toLong * 8
    var i = 0
    while (i < 8) {
      thePad(thePad.length - 1 - i) = ((lengthInBits >>> (8 * i)) & 0xff).toByte
      i += 1
    }

    val padded = new Array[Byte](origLength + padLength)
    System.arraycopy(message, 0, padded, 0, origLength)
    System.arraycopy(thePad, 0, padded, origLength, thePad.length)

    padded
  }

  def padding_64(message: Array[Byte]): Array[Byte] = {
    val origLength = message.length
    val tailLength = origLength & 0x7f
    val padLength = if (tailLength < 112) 128 - tailLength else 256 - tailLength

    val thePad = new Array[Byte](padLength)
    thePad(0) = 0x80.toByte

    val lengthInBits = origLength.toLong * 8
    var i = 0
    while (i < 8) {
      thePad(thePad.length - 1 - i) = ((lengthInBits >>> (8 * i)) & 0xff).toByte
      i += 1
    }

    val padded = new Array[Byte](origLength + padLength)
    System.arraycopy(message, 0, padded, 0, origLength)
    System.arraycopy(thePad, 0, padded, origLength, thePad.length)

    padded
  }

}
