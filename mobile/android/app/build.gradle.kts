plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

val releaseVersion = providers.environmentVariable("ACTIVECHAIN_RELEASE_VERSION").orNull
val releaseBuild = providers.environmentVariable("ACTIVECHAIN_RELEASE_BUILD").orNull
val signingNames = listOf("ACTIVECHAIN_ANDROID_KEYSTORE", "ACTIVECHAIN_ANDROID_STORE_PASSWORD",
    "ACTIVECHAIN_ANDROID_KEY_ALIAS", "ACTIVECHAIN_ANDROID_KEY_PASSWORD")
val signingValues = signingNames.associateWith { providers.environmentVariable(it).orNull }
val signingReady = signingValues.values.all { !it.isNullOrBlank() }

android { namespace = "dev.activechain.wallet"; compileSdk = 35
    defaultConfig { applicationId = "dev.activechain.wallet"; minSdk = 26; targetSdk = 35
        versionCode = releaseBuild?.toIntOrNull() ?: 1
        versionName = releaseVersion ?: "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
    if (signingReady) {
        signingConfigs.create("storeRelease") {
            storeFile = file(signingValues.getValue("ACTIVECHAIN_ANDROID_KEYSTORE")!!)
            storePassword = signingValues.getValue("ACTIVECHAIN_ANDROID_STORE_PASSWORD")
            keyAlias = signingValues.getValue("ACTIVECHAIN_ANDROID_KEY_ALIAS")
            keyPassword = signingValues.getValue("ACTIVECHAIN_ANDROID_KEY_PASSWORD")
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("storeRelease")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
    sourceSets["androidTest"].assets.srcDir(rootProject.projectDir.resolve("../../testing/vectors"))
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
}

val buildRustWallet = tasks.register<Exec>("buildRustWallet") {
    val output = layout.buildDirectory.dir("generated/jniLibs")
    val repository = rootProject.projectDir.resolve("../..")
    inputs.files(
        repository.resolve("Cargo.toml"),
        repository.resolve("Cargo.lock"),
        repository.resolve("scripts/build-android-wallet-library.sh"),
        fileTree(repository.resolve("crates")) {
            include("**/Cargo.toml", "**/*.rs")
        },
    )
    outputs.dir(output)
    commandLine(
        rootProject.projectDir.resolve("../../scripts/build-android-wallet-library.sh"),
        output.get().asFile,
    )
}

tasks.named("preBuild").configure { dependsOn(buildRustWallet) }

gradle.taskGraph.whenReady {
    if (allTasks.any { it.project == project && it.name in setOf("bundleRelease", "assembleRelease", "packageReleaseBundle") }) {
        require(signingReady) { "Release signing is incomplete: configure ${signingNames.joinToString()}" }
        require(releaseVersion?.matches(Regex("(?:0|[1-9][0-9]{0,3})(?:\\.(?:0|[1-9][0-9]{0,3})){2}")) == true) {
            "ACTIVECHAIN_RELEASE_VERSION must contain three numeric components"
        }
        require((releaseBuild?.toIntOrNull() ?: 0) in 1..2_100_000_000) {
            "ACTIVECHAIN_RELEASE_BUILD must be a unique integer in 1..2100000000"
        }
    }
}
