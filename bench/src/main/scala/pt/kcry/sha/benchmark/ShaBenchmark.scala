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
package benchmark

import org.openjdk.jmh.annotations._

import java.security.MessageDigest
import scala.util.Random

@State(Scope.Benchmark)
class ShaBenchmark {

  private val hashedSha1: Array[Byte] = new Array[Byte](Sha1.HASH_SIZE)

  private val hashedSha256: Array[Byte] = new Array[Byte](Sha2_256.HASH_SIZE)

  private val hashedSha512: Array[Byte] = new Array[Byte](Sha2_512.HASH_SIZE)

  @Param(Array("1024", "16384"))
  private var len: Int = 0

  private var data: Array[Byte] = _

  @Setup
  def prepare(): Unit = {
    data = new Array[Byte](len)
    Random.nextBytes(data)
  }

  @Benchmark
  def sha1(): Unit = {
    val hasher = new Sha1()
    hasher.update(data, 0, len)
    hasher.finish(hashedSha1, 0)
  }

  @Benchmark
  def jvmSha1(): Unit = {
    val md = MessageDigest.getInstance("SHA-1")
    md.update(data)
    md.digest(hashedSha1)
  }

  @Benchmark
  def sha256(): Unit = {
    val hasher = new Sha2_256()
    hasher.update(data, 0, len)
    hasher.finish(hashedSha256, 0)
  }

  @Benchmark
  def jvmSha256(): Unit = {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(data)
    md.digest(hashedSha256)
  }

  @Benchmark
  def sha512(): Unit = {
    val hasher = new Sha2_512()
    hasher.update(data, 0, len)
    hasher.finish(hashedSha512, 0)
  }

  @Benchmark
  def jvmSha512(): Unit = {
    val md = MessageDigest.getInstance("SHA-512")
    md.update(data)
    md.digest(hashedSha512)
  }

  @Benchmark
  def sha3_256(): Unit = {
    val hasher = new Sha3_256()
    hasher.update(data, 0, len)
    hasher.finish(hashedSha256, 0)
  }

  @Benchmark
  def jvmSha3_256(): Unit = {
    val md = MessageDigest.getInstance("SHA3-256")
    md.update(data)
    md.digest(hashedSha256)
  }

  @Benchmark
  def sha3_512(): Unit = {
    val hasher = new Sha3_512()
    hasher.update(data, 0, len)
    hasher.finish(hashedSha512, 0)
  }

  @Benchmark
  def jvmSha3_512(): Unit = {
    val md = MessageDigest.getInstance("SHA3-512")
    md.update(data)
    md.digest(hashedSha512)
  }
}
