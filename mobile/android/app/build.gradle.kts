plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android { namespace = "dev.activechain.wallet"; compileSdk = 35
    defaultConfig { applicationId = "dev.activechain.wallet"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "0.1.0-dev"; testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
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
