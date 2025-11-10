plugins {
    kotlin("jvm") version "1.9.20"
    `maven-publish`
}

group = "io.github.bardoquant"
version = "2.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    implementation("org.bouncycastle:bcprov-ext-jdk18on:1.77")
    implementation("org.bouncycastle:bcutil-jdk18on:1.77")
    
    implementation("com.google.code.gson:gson:2.10.1")
    
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

java {
    withSourcesJar()
    withJavadocJar()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            
            pom {
                name.set("BardoQuant Encryption")
                description.set("Post-quantum cryptography encryption library with CRYSTALS-Kyber768")
                url.set("https://github.com/yourusername/bardo-quant")
                
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                
                developers {
                    developer {
                        id.set("bardoquant")
                        name.set("BardoQuantum Security Team")
                    }
                }
                
                scm {
                    connection.set("scm:git:git://github.com/yourusername/bardo-quant.git")
                    developerConnection.set("scm:git:ssh://github.com/yourusername/bardo-quant.git")
                    url.set("https://github.com/yourusername/bardo-quant")
                }
            }
        }
    }
}

