pluginManagement {
    repositories {
        // 优先：官方/谷歌
        google()
        mavenCentral()
        gradlePluginPortal()
        // 回退：阿里云镜像
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/public")
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // 优先：官方/谷歌
        google()
        mavenCentral()
        // 回退：阿里云镜像
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
    }
}

rootProject.name = "CVE-2026-98260"
include(":app")
