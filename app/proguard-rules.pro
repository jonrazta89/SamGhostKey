# ============================================================
# GhostKey R8 混淆规则（方案：kernel-adaptation-plan-final.md 第九/十三章）
# ============================================================

# ===== 保留规则 =====

# Shizuku UserService：以字符串类名传给 ComponentName，由 Shizuku 反射实例化，
# 类名一旦混淆直接 ClassNotFoundException
-keep class com.EternalTimes.GhostKey.shizuku.Cve98260UserService { *; }

# AIDL 接口与 Stub：跨进程 Binder 序列化，DESCRIPTOR/CREATOR 反射访问
-keep class com.EternalTimes.GhostKey.shizuku.ICve98260UserService { *; }
-keep class com.EternalTimes.GhostKey.shizuku.ICve98260UserService$* { *; }
-keep class com.EternalTimes.GhostKey.shizuku.ICve98260Callback { *; }
-keep class com.EternalTimes.GhostKey.shizuku.ICve98260Callback$* { *; }

# ViewModel：AndroidViewModelFactory 通过反射 getConstructor 创建实例
-keep class com.EternalTimes.GhostKey.viewmodel.ExploitViewModel {
    <init>(android.app.Application);
}

# 反射/泛型安全所需的属性（Kotlin 反射、协程、Compose 均依赖）
-keepattributes Signature, InnerClasses, EnclosingMethod, *Annotation*

# ===== 混淆规则 =====

# 混淆所有其他类名/方法名，并统一重打包到根包，缩短标识符
-repackageclasses ''
-allowaccessmodification

# ===== 日志裁剪 =====
# 移除 verbose / debug 日志调用（release 瘦身 + 降噪；i/w/e 保留便于排障）
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
