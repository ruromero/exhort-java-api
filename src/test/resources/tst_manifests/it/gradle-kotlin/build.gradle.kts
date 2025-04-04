plugins {
    id("java")
}

group = "org.acme.dbaas"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.quarkus:quarkus-jdbc-postgresql:2.13.5.Final")
}

tasks.test {
    useJUnitPlatform()
}
