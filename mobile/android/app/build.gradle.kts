plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android { namespace = "dev.activechain.wallet"; compileSdk = 35
    defaultConfig { applicationId = "dev.activechain.wallet"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "0.1.0-dev"; testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
}
