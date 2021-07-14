# SHA and Shake for scala

This is Secure Hash Algorithms family which is implemented for scala, scala-js
and scala-native, without any dependencies.

This code base implements SHA-0, SHA-1, SHA-2 and SHA-3. Keep in mind that SHA-0
is broken and I've implemented it just for fun :)

This code wasn't designed to be as fast as possible. I tried my best to make
implementation fast when I did it, but I haven't done any benchmarks yet. Will I
make it one day faster or oriented to huge chunks? Probably.

The propose of this code to be fast enough to hash something up to a few
megabytes at the worst case and at few kilobytes as usual case. Where? At any
scala-based application where hashing isn't the bottleneck.

This assumption also included inside API: it consumes whole provided array, it
allocates and copies a lot.

If you need fast and secure hash function for scala I suggest to use
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

[maven-central]: https://img.shields.io/maven-central/v/ky.korins/sha_2.13?style=flat-square
