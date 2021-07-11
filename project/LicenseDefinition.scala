import de.heikoseeberger.sbtheader.HeaderPlugin.autoImport.HeaderLicense
import de.heikoseeberger.sbtheader.License
import sbt.url

object LicenseDefinition {
  val template: Option[License.Custom] = Some(
    HeaderLicense.Custom(
      """scala-sha - Secure Hash Algorithms family for scala, scala-js and scala-native.
      |
      |Written in 2020, 2021 by Kirill A. Korinsky <kirill@korins.ky>
      |
      |This work is released into the public domain with CC0 1.0.
      |""".stripMargin
    )
  )

  val licenses = Seq(
    "CC0 1.0 Universal" -> url(
      "https://github.com/catap/scala-sha/blob/master/LICENSE.txt"
    ),
    "Apache License 2.0" -> url(
      "https://github.com/catap/scala-sha/blob/master/LICENSE.txt"
    )
  )
}
