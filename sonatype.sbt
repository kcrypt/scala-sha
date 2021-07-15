import sbt.url
import xerial.sbt.Sonatype.GitHubHosting

ThisBuild / sonatypeProfileName := "ky.korins"
ThisBuild / publishMavenStyle := true
ThisBuild / sonatypeProjectHosting := Some(
  GitHubHosting("catap", "scala-sha", "kirill@korins.ky")
)
ThisBuild / licenses := LicenseDefinition.licenses
ThisBuild / homepage := Some(url("https://github.com/catap/scala-sha"))
ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/catap/scala-sha"),
    "scm:git@github.com:catap/scala-sha.git"
  )
)
ThisBuild / developers := List(
  Developer(
    id = "catap",
    name = "Kirill A. Korinsky",
    email = "kirill@korins.ky",
    url = url("https://github.com/catap")
  )
)
