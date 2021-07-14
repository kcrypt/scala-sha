# SHA and Shake for scala

This is Secure Hash Algorithms family which is implemented for scala, scala-js
and scala-native, without any dependencies.

This code base implements SHA-0, SHA-1, SHA-2 and SHA-3. Keep in mind that SHA-0
is broken and I've implemented it just for fun :)

The propose of this code to be fast enough to hash something up to a few
megabytes at the worst case and at few kilobytes as usual case. Where? At any
scala-based application where hashing isn't the bottleneck. This code hasn't got
any CPU related optimizations, nor multithreading features for Keccak / SHA-3.

If you need very fast and secure hash function for scala I suggest to use
[blake3](https://github.com/catap/scala-blake3).

You can use it as
```
libraryDependencies += "ky.korins" %%% "sha" % "x.x.x"
```
The latest version is ![maven-central]

API is pretty simple and quite limited :)
```
scala> import ky.korins.sha._
import ky.korins.sha._

scala> Sha2_256.hash("abc".getBytes())
val res1: Array[Byte] = Array(-70, 120, 22, -65, -113, 1, -49, -22, 65, 65, 64, -34, 93, -82, 34, 35, -80, 3, 97, -93, -106, 23, 122, -100, -76, 16, -1, 97, -14, 0, 21, -83)

scala> 
```

You may also create a new object from specified hash to `update` it, and at some
point `finish` it like this:
```
scala> import ky.korins.sha._
import ky.korins.sha._

scala> val sha1 = new Sha1()
val sha1: ky.korins.sha.Sha1 = ky.korins.sha.Sha1@1224e1b6

scala> sha1.update("abc".getBytes(), 0, 2)

scala> sha1.update("abc".getBytes(), 2, 1)

scala> val hashed = new Array[Byte](20)
val hashed: Array[Byte] = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

scala> sha1.finish(hashed, 0)

scala> hashed
val res3: Array[Byte] = Array(-87, -103, 62, 54, 71, 6, -127, 106, -70, 62, 37, 113, 120, 80, -62, 108, -100, -48, -40, -99)

scala> 
```

All these objects aren't thread safe. After `finish` it should be treated as
broken.

Anyway, I did a few benchmarks to compare this implementation with JVM one
which was run on `JDK 11.0.11, OpenJDK 64-Bit Server VM, 11.0.11+9-LTS`:
```
Benchmark                 (len)  Mode  Cnt    Score   Error  Units
ShaBenchmark.jvmSha1       1024  avgt    5    3,686 ± 0,005  us/op
ShaBenchmark.jvmSha1      16384  avgt    5   55,556 ± 1,103  us/op
ShaBenchmark.jvmSha256     1024  avgt    5    4,326 ± 0,012  us/op
ShaBenchmark.jvmSha256    16384  avgt    5   61,924 ± 0,025  us/op
ShaBenchmark.jvmSha3_256   1024  avgt    5    4,129 ± 0,045  us/op
ShaBenchmark.jvmSha3_256  16384  avgt    5   61,627 ± 1,422  us/op
ShaBenchmark.jvmSha3_512   1024  avgt    5    7,974 ± 0,091  us/op
ShaBenchmark.jvmSha3_512  16384  avgt    5  111,711 ± 0,372  us/op
ShaBenchmark.jvmSha512     1024  avgt    5    3,172 ± 0,001  us/op
ShaBenchmark.jvmSha512    16384  avgt    5   44,205 ± 0,024  us/op
ShaBenchmark.sha1          1024  avgt    5    4,285 ± 0,002  us/op
ShaBenchmark.sha1         16384  avgt    5   64,380 ± 0,022  us/op
ShaBenchmark.sha256        1024  avgt    5    4,330 ± 0,005  us/op
ShaBenchmark.sha256       16384  avgt    5   63,293 ± 0,024  us/op
ShaBenchmark.sha3_256      1024  avgt    5    5,919 ± 0,019  us/op
ShaBenchmark.sha3_256     16384  avgt    5   84,952 ± 0,468  us/op
ShaBenchmark.sha3_512      1024  avgt    5    8,114 ± 0,078  us/op
ShaBenchmark.sha3_512     16384  avgt    5  118,706 ± 0,924  us/op
ShaBenchmark.sha512        1024  avgt    5    3,168 ± 0,007  us/op
ShaBenchmark.sha512       16384  avgt    5   44,630 ± 0,017  us/op
```

[maven-central]: https://img.shields.io/maven-central/v/ky.korins/sha_2.13?style=flat-square
