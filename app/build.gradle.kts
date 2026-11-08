import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * 基础版本号（不含变体标识）。正式版与 test 变体共用同一个基础版本号，
 * 便于对照「这是 2.1.0 的第几个构建」。
 */
val appVersionBase = "2.2.0"

/**
 * 变体标识。test 变体在版本名后加 `-test`：
 * 界面标题显示 `v2.1.0-test · <commit>`、系统「应用信息」里也显示 2.1.0-test，
 * 不会和将来的正式版 2.1.0 混淆（之前 test 包直接用 `2.1.0`，一眼看去
 * 跟正式版一模一样，这是真机实测时发现并修掉的）。
 * alpha 预发布用 `alphaNN`（如 2.1.0-alpha01），沿用 .test 包名与发布方式。
 */
val variantLabel = "alpha07"

/**
 * 最终版本名，例如 `2.1.0-test`。变体标识为空时就是基础版本号本身
 * （将来转正式版时把 variantLabel 置空即可，不会留下多余的连字符）。
 */
val appVersionName = listOf(appVersionBase, variantLabel)
    .filter { it.isNotBlank() }
    .joinToString("-")

/**
 * 测试变体标记：非空时 applicationId 加 `.test` 后缀、产物名加 `-test`，
 * 可与正式版（com.EternalTimes.GhostKey）**并存安装**，互不覆盖。
 *
 * 2.1.0 走这条路线：这一版是失败路径加固 + mlockall 保护修复，属于
 * 「先在测试包上验证」的性质，正式包 2.0.0 暂不动。
 */
val testVariantSuffix = ".test"

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

/**
 * 取当前构建所在提交的短 id（git rev-parse --short HEAD），供界面显示「版本 · 提交」。
 * 非 git 环境或执行失败时回退 "unknown"，绝不阻断构建。
 */
fun gitShortCommit(): String = try {
    val p = ProcessBuilder("git", "rev-parse", "--short", "HEAD")
        .directory(rootProject.rootDir)
        .redirectErrorStream(true)
        .start()
    val out = p.inputStream.bufferedReader().readText().trim()
    if (p.waitFor() == 0 && out.isNotBlank()) out else "unknown"
} catch (_: Exception) {
    "unknown"
}

android {
    namespace = "com.EternalTimes.GhostKey"
    compileSdk = 37
    compileSdkMinor = 2

    defaultConfig {
        // 测试变体：.test 包名可与正式版并存安装（见 testVariantSuffix 的说明）
        applicationId = "com.EternalTimes.GhostKey$testVariantSuffix"
        minSdk = 31
        targetSdk = 37
        /**
         * versionCode 分两条线，互不占用：
         *   · 正式版线（com.EternalTimes.GhostKey）      小整数递增：1.1.4=17 … 2.0.0=24
         *   · test 线   （com.EternalTimes.GhostKey.test）独立号段：2.0.0-alpha01..03 = 20001..20003，
         *     2.1.0 线 = 21001（-test 构建）/ 21002（2.1.0-alpha01），2.2.0 线 = 22002（2.2.0-alpha01）/ 22003（2.2.0-alpha02）/ 22004（2.2.0-alpha03）
         *     / 22005（alpha04）/ 22006（alpha05）/ 22007（alpha06）/ 22008（alpha07）
         *     （次版本号 → 对应号段，2.2 → 22xxx）。
         * 之前 test 包直接用了 25 —— 那是正式版线的下一个号，正式版 2.1.0 发布时
         * 必然撞号；两者的包名不同，Android 不会拦，但号段混在一起以后很难排查。
         */
        versionCode = 22008
        versionName = appVersionName
        // 界面显示用：注入当前 git 短提交 id（VERSION_NAME 由 AGP 自动写入 BuildConfig）
        buildConfigField("String", "GIT_COMMIT", "\"${gitShortCommit()}\"")

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
        sourceCompatibility = JavaVersion.VERSION_27
        targetCompatibility = JavaVersion.VERSION_27
    }

    buildFeatures {
        compose = true
        aidl = true
        buildConfig = true
    }

    lint {
        // Cve98260UserService 是 Shizuku UserService（非标准 android.app.Service），
        // Manifest 中的声明是 Shizuku 模式要求，Instantiatable 检查在此属误报
        disable += "Instantiatable"
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(27))
        }
    }

    // AGP 9.6 预览版新增的 generate<Variant>ComposePreviewRunfiles 在配置期建任务，
    // 要求单测包含 Android 资源（否则 IDE Gradle 同步直接失败）；打开后纯 JVM 单测不受影响
    testOptions {
        unitTests.isIncludeAndroidResources = true
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

// AGP 9 内置 Kotlin：kotlinOptions DSL 已移除，改用顶层 kotlin{} 的 compilerOptions
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_27)
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(27))
    }
}

/**
 * 内置 ksud 完整性校验（JVM 原生 SHA-256，不依赖 python/外部工具链）。
 *
 * 内置 assets/ksu/ksud 是手工投放的二进制，KMI 集冻结在打包时刻；一旦有人换了二进制
 * 却没同步清单（或误替换成不兼容构建），这条校验会在任意构建（preBuild）时拦下。
 * 换二进制后跑 `python3 tool/check_ksud.py --update` 就地同步清单的 sha256/size。
 */
val ksudAsset = file("src/main/assets/ksu/ksud")
val ksudManifest = file("src/main/assets/ksu/ksud.manifest")

val verifyBundledKsud = tasks.register("verifyBundledKsud") {
    group = "verification"
    description = "校验内置 ksud 与 ksud.manifest 的 sha256/size 一致"
    inputs.file(ksudAsset)
    inputs.file(ksudManifest)
    doLast {
        if (!ksudAsset.isFile) throw GradleException("内置 ksud 缺失: $ksudAsset")
        if (!ksudManifest.isFile) throw GradleException("ksud 清单缺失: $ksudManifest")
        val text = ksudManifest.readText()
        val expSha = Regex("\"sha256\"\\s*:\\s*\"([0-9a-fA-F]+)\"").find(text)?.groupValues?.get(1)?.lowercase()
        val expSize = Regex("\"size_bytes\"\\s*:\\s*(\\d+)").find(text)?.groupValues?.get(1)?.toLongOrNull()
        val sha = MessageDigest.getInstance("SHA-256").let { md ->
            ksudAsset.inputStream().use { ins ->
                val buf = ByteArray(1 shl 20)
                var n = ins.read(buf)
                while (n > 0) {
                    md.update(buf, 0, n)
                    n = ins.read(buf)
                }
            }
            md.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
        val size = ksudAsset.length()
        val problems = mutableListOf<String>()
        if (expSize != size) problems += "size 不符: 清单 $expSize, 实际 $size"
        if (expSha != sha) problems += "sha256 不符:\n  清单 $expSha\n  实际 $sha"
        if (problems.isNotEmpty()) {
            throw GradleException(
                "内置 ksud 与清单不一致。若确已更换二进制，运行 `python3 tool/check_ksud.py --update` 同步清单后重试：\n" +
                    problems.joinToString("\n"),
            )
        }
        logger.lifecycle("verifyBundledKsud: OK (size=$size sha256=$sha)")
    }
}

tasks.named("preBuild") { dependsOn(verifyBundledKsud) }

// 产物文件名：GhostKey-<版本>-<abi>-<buildtype>.apk；测试变体版本名已含变体标识，
// 如 GhostKey-2.2.0-alpha01-arm64-v8a-release.apk，避免与正式版撞名
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
