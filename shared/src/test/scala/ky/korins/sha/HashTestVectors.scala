/*
 * scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
 *
 * Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
 *
 * This work is released into the public domain with CC0 1.0.
 */

package ky.korins.sha

import org.scalatest._
import org.scalatest.matchers.should

import scala.language.implicitConversions

class HashTestVectors extends wordspec.AsyncWordSpec with should.Matchers {

  /**
   * Source of test vectors: https://www.di-mgt.com.au/sha_testvectors.html
   *
   * This hash wasn't implemented to hash something huge.
   *
   * This mean that I skip the extremely-long message vector.
   *
   * Also, SHA-0 and Shakes aren't a part of this test vector => I've computed it by hand.
   */
  "DI Management test vectors" when {
    "length 24 bits" in {
      "abc" sha0_shouldBe "0164b8a9 14cd2a5e 74c4f7ff 082c4d97 f1edf880"
      "abc" sha1_shouldBe "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"
      "abc" sha2_224_ShouldBe "23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7"
      "abc" sha2_256_ShouldBe "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"
      "abc" sha2_384_ShouldBe "cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7"
      "abc" sha2_512_ShouldBe "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"
      "abc" sha3_224_ShouldBe "e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf"
      "abc" sha3_256_ShouldBe "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532"
      "abc" sha3_384_ShouldBe "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25"
      "abc" sha3_512_ShouldBe "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0"
      "abc" shake_128_ShouldBe "5881092dd818bf5cf8a3ddb793"
      "abc" shake_256_ShouldBe "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b57"
    }

    "length 0 bits" in {
      "" sha0_shouldBe "f96cea19 8ad1dd56 17ac084a 3d92c610 7708c0ef"
      "" sha1_shouldBe "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709"
      "" sha2_224_ShouldBe "d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f"
      "" sha2_256_ShouldBe "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"
      "" sha2_384_ShouldBe "38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b"
      "" sha2_512_ShouldBe "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"
      "" sha3_224_ShouldBe "6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7"
      "" sha3_256_ShouldBe "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a"
      "" sha3_384_ShouldBe "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004"
      "" sha3_512_ShouldBe "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26"
      "" shake_128_ShouldBe "7f9c2ba4e88f827d6160455076"
      "" shake_256_ShouldBe "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed576"
    }

    "length 448 bits" in {
      val input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      input sha0_shouldBe "d2516ee1 acfa5baf 33dfc1c4 71e43844 9ef134c8"
      input sha1_shouldBe "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"
      input sha2_224_ShouldBe "75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525"
      input sha2_256_ShouldBe "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1"
      input sha2_384_ShouldBe "3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b"
      input sha2_512_ShouldBe "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445"
      input sha3_224_ShouldBe "8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33"
      input sha3_256_ShouldBe "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376"
      input sha3_384_ShouldBe "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22"
      input sha3_512_ShouldBe "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e"
      input shake_128_ShouldBe "1a96182b50fb8c7e74e0a70778"
      input shake_256_ShouldBe "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e33"
    }

    "length 896 bits" in {
      val input =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      input sha0_shouldBe "459f83b9 5db2dc87 bb0f5b51 3a28f900 ede83237"
      input sha1_shouldBe "a49b2446 a02c645b f419f995 b6709125 3a04a259"
      input sha2_224_ShouldBe "c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3"
      input sha2_256_ShouldBe "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1"
      input sha2_384_ShouldBe "09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039"
      input sha2_512_ShouldBe "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909"
      input sha3_224_ShouldBe "543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc"
      input sha3_256_ShouldBe "916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18"
      input sha3_384_ShouldBe "79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7"
      input sha3_512_ShouldBe "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185"
      input shake_128_ShouldBe "7b6df6ff181173b6d7898d7ff6"
      input shake_256_ShouldBe "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf"
    }

    "one million repetitions of the a" in {
      val input = (0 until 1000000).map(_ => 'a').mkString
      input sha0_shouldBe "3232affa 48628a26 653b5aaa 44541fd9 0d690603"
      input sha1_shouldBe "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f"
      input sha2_224_ShouldBe "20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67"
      input sha2_256_ShouldBe "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0"
      input sha2_384_ShouldBe "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985"
      input sha2_512_ShouldBe "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b"
      input sha3_224_ShouldBe "d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c"
      input sha3_256_ShouldBe "5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1"
      input sha3_384_ShouldBe "eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340"
      input sha3_512_ShouldBe "3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87"
      input shake_128_ShouldBe "9d222c79c4ff9d092cf6ca8614"
      input shake_256_ShouldBe "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd1"
    }
  }

  case class RichString(str: String) {
    def sha0_shouldBe(expected: Array[Byte]): Assertion =
      Sha0.hash(str.getBytes()) shouldBe expected

    def sha1_shouldBe(expected: Array[Byte]): Assertion =
      Sha1.hash(str.getBytes()) shouldBe expected

    def sha2_224_ShouldBe(expected: Array[Byte]): Assertion =
      Sha2_224.hash(str.getBytes()) shouldBe expected

    def sha2_256_ShouldBe(expected: Array[Byte]): Assertion =
      Sha2_256.hash(str.getBytes()) shouldBe expected

    def sha2_384_ShouldBe(expected: Array[Byte]): Assertion =
      Sha2_384.hash(str.getBytes()) shouldBe expected

    def sha2_512_ShouldBe(expected: Array[Byte]): Assertion =
      Sha2_512.hash(str.getBytes()) shouldBe expected

    def sha3_224_ShouldBe(expected: Array[Byte]): Assertion =
      Sha3_224.hash(str.getBytes()) shouldBe expected

    def sha3_256_ShouldBe(expected: Array[Byte]): Assertion =
      Sha3_256.hash(str.getBytes()) shouldBe expected

    def sha3_384_ShouldBe(expected: Array[Byte]): Assertion =
      Sha3_384.hash(str.getBytes()) shouldBe expected

    def sha3_512_ShouldBe(expected: Array[Byte]): Assertion =
      Sha3_512.hash(str.getBytes()) shouldBe expected

    def shake_128_ShouldBe(expected: Array[Byte]): Assertion =
      Shake_128.hash(str.getBytes(), 13) shouldBe expected

    def shake_256_ShouldBe(expected: Array[Byte]): Assertion =
      Shake_256.hash(str.getBytes(), 31) shouldBe expected
  }

  implicit def string2richString(str: String): RichString = RichString(str)

  implicit def hex2bytes(hex: String): Array[Byte] = {
    val chunks = hex.replace(" ", "").sliding(2, 2).toArray
    chunks.map(Integer.parseInt(_, 16).toByte)
  }
}
