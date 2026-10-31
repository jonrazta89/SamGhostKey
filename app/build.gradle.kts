import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val appVersionName = "1.1.8"

/**
 * 签名密码加载：优先从 local.properties（已被 .gitignore 忽略，不会进入版本库）读取，
 * 其次从同名环境变量读取；二者皆缺时抛出明确错误，提示开发者配置，
 * 避免把明文密码写回源码（此前曾把 Cve98260ReleaseKey2026 硬编码在 signingConfigs 中）。
 *
 * 注意：这里必须写 `Properties()` 而不是 `java.util.Properties()`——脚本作用域里的
 * `java` 已被 Android 的 JavaPluginExtension 占用，全限定写法会解析成扩展的成员而报错。
 */
fun loadSigningPassword(propName: String): String {
    val localProps = File(rootProject.rootDir, "local.properties")
    if (localProps.exists()) {
        val props = Properties()
        FileInputStream(localProps).use { props.load(it) }
        props.getProperty(propName)?.takeIf { it.isNotBlank() }?.let { return it }
    }
    System.getenv(propName)?.takeIf { it.isNotBlank() }?.let { return it }
    throw GradleException(
        "缺少签名密码 '$propName'。请在 local.properties 中添加：$propName=<你的密码> " +
            "（local.properties 已被 .gitignore 忽略，不会被提交），或通过环境变量提供。",
    )
}

android {
    namespace = "com.EternalTimes.GhostKey"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.EternalTimes.GhostKey"
        minSdk = 31
        targetSdk = 35
        versionCode = 21
        versionName = appVersionName

        externalNativeBuild {
            cmake {
                arguments("-DANDROID_STL=none")
                cppFlags("")
            }
        }
    }

    signingConfigs {
        create("release") {
            storeFile = file("keystore/release.keystore")
        storePassword = loadSigningPassword("CVE98260_STORE_PASSWORD")
        keyAlias = "cve98260"
        keyPassword = loadSigningPassword("CVE98260_KEY_PASSWORD")
            storeType = "PKCS12"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        aidl = true
    }

    lint {
        // Cve98260UserService 是 Shizuku UserService（非标准 android.app.Service），
        // Manifest 中的声明是 Shizuku 模式要求，Instantiatable 检查在此属误报
        disable += "Instantiatable"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    splits {
        abi {
            isEnable = true
            isUniversalApk = false
            reset()
            include("arm64-v8a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

// 产物文件名统一为 GhostKey-<版本>-*（如 GhostKey-1.1.2-arm64-v8a-release.apk）
base {
    archivesName.set("GhostKey-$appVersionName")
}

dependencies {
    // Compose
    implementation(platform("androidx.compose:compose-bom:2024.10.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")

    // Shizuku
    val shizukuVersion = "13.1.5"
    implementation("dev.rikka.shizuku:api:$shizukuVersion")
    implementation("dev.rikka.shizuku:provider:$shizukuVersion")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Core
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")

    // 单测：StageTracker 的纯逻辑验证
    testImplementation("junit:junit:4.13.2")
}
