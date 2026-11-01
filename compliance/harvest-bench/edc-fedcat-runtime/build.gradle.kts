// Real Eclipse EDC 0.18.0 *federated-catalog crawler* runtime - EDC's own
// harvesting component, not the participant-side control-plane fixture in
// ../../crawler-edc-fixture (that project seeds assets a participant
// *serves*; this one crawls other participants' DSP catalog endpoints and
// aggregates results, the same job crates/crawler does from scratch in
// Rust). Built directly from published Maven Central artifacts, no
// vendored source touched, same recipe as ../../crawler-edc-fixture's own
// build.gradle.kts.
//
// `org.eclipse.edc:federatedcatalog-base-bom:0.18.0` is a real, published
// aggregator - confirmed by fetching its POM from repo1.maven.org before
// depending on it - that bundles catalog-crawler-core, federated-catalog-api,
// federated-catalog-spi, the Management API stack (management-api-configuration,
// auth-tokenbased, jersey/jetty), the DSP protocol stack, and boot/runtime
// machinery. It does NOT bundle an IdentityService (needed both to satisfy
// DspHttpCoreExtension's hard @Inject at boot and to mint the outbound
// Authorization header the crawler sends to each crawled participant) -
// `org.eclipse.edc:iam-mock:0.18.0` supplies one, confirmed to resolve on
// Maven Central and confirmed as the correct pairing by reading
// eclipse-edc-connector's own end-to-end federated-catalog test
// (system-tests/e2e-federatedcatalog-tests/end2end-test/e2e-junit-runner/.../FederatedCatalogTest.java),
// which wires exactly this pair (":dist:bom:federatedcatalog-base-bom" +
// ":extensions:common:iam:iam-mock") for its own embedded catalog runtime.
plugins {
    java
}

repositories {
    mavenCentral()
}

// -PedcVersion=<version> selects the EDC release (default: the latest benchmarked,
// 1.0.0-RC5). 0.18.0 was used by the 2026-08-27 report.
// dsp-catalog-transform-2025 is listed explicitly: federatedcatalog-base-bom
// 1.0.0-RC5 no longer brings the transformer for the outgoing
// CatalogRequestMessage, so every crawl failed without any log line.
val edcVersion = (findProperty("edcVersion") as String?) ?: "1.0.0-RC5"

dependencies {
    implementation("org.eclipse.edc:federatedcatalog-base-bom:$edcVersion")
    implementation("org.eclipse.edc:iam-mock:$edcVersion")
    implementation("org.eclipse.edc:dsp-catalog-transform-2025:$edcVersion")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

// Same pattern as ../../crawler-edc-fixture/build.gradle.kts's own
// printClasspath task - writes the full runtime classpath so run-instance.sh
// can launch a plain `java -cp ...` process with no Gradle daemon needed
// for the long-running instance itself.
tasks.register("printClasspath") {
    dependsOn(tasks.named("classes"))
    doLast {
        val cp = sourceSets["main"].runtimeClasspath.files.joinToString(":") { it.absolutePath }
        val out = layout.buildDirectory.file("classpath.txt").get().asFile
        out.parentFile.mkdirs()
        out.writeText(cp)
        println("wrote ${out.absolutePath} (${sourceSets["main"].runtimeClasspath.files.size} entries)")
    }
}
