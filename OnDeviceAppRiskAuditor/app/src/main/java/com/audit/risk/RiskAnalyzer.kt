package com.audit.risk

import android.content.Context
import android.content.pm.PackageManager

object RiskAnalyzer {

    fun getInstalledApps(context: Context, includeSystem: Boolean): List<AppModel> {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA)
        val appList = mutableListOf<AppModel>()

        for (pkg in packages) {
            val isSystem = (pkg.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
            if (!includeSystem && isSystem) continue

            val appName = pm.getApplicationLabel(pkg.applicationInfo).toString()
            val packageName = pkg.packageName ?: ""
            val versionName = pkg.versionName ?: "1.0"
            val installDate = pkg.firstInstallTime
            val targetSdk = pkg.applicationInfo.targetSdkVersion
            
            val installerSource = try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    pm.getInstallSourceInfo(packageName).installingPackageName ?: "Unknown/Sideloaded"
                } else {
                    pm.getInstallerPackageName(packageName) ?: "Unknown/Sideloaded"
                }
            } else {
                "Unknown"
            }

            val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val (score, band, reasons) = calculateRisk(appName, permissions, installerSource)

            appList.add(
                AppModel(
                    appName = appName,
                    packageName = packageName,
                    versionName = versionName,
                    installDate = installDate,
                    isSystemApp = isSystem,
                    installerSource = installerSource,
                    targetSdk = targetSdk,
                    grantedPermissions = permissions,
                    riskScore = score,
                    riskBand = band,
                    riskReasons = reasons
                )
            )
        }
        return appList.sortedByDescending { it.riskScore }
    }

    private fun calculateRisk(appName: String, permissions: List<String>, installerSource: String): Triple<Int, String, List<String>> {
        var score = 10 
        val reasons = mutableListOf<String>()

        // 1. Special Access check (Highest Weight as per PS-01 guidelines)
        val hasAccessibility = permissions.any { it.contains("BIND_ACCESSIBILITY_SERVICE", ignoreCase = true) }
        val hasOverlay = permissions.any { it.contains("SYSTEM_ALERT_WINDOW", ignoreCase = true) }
        val hasDeviceAdmin = permissions.any { it.contains("BIND_DEVICE_ADMIN", ignoreCase = true) }

        if (hasAccessibility) {
            score += 35
            reasons.add("Holds Accessibility Service access (can read screen content & automate clicks)")
        }
        if (hasOverlay) {
            score += 25
            reasons.add("Can draw over other apps (risk of phishing overlays)")
        }
        if (hasDeviceAdmin) {
            score += 30
            reasons.add("Active Device Admin privileges (uninstall blocking potential)")
        }

        // 2. SMS & Call Logs category checks
        val hasSms = permissions.any { it.contains("SMS", ignoreCase = true) }
        if (hasSms) {
            score += 20
            reasons.add("Requests SMS permissions (OTP theft vulnerability)")
        }

        // 3. Background & Persistence category check
        val hasBoot = permissions.any { it.contains("RECEIVE_BOOT_COMPLETED", ignoreCase = true) }
        if (hasBoot) {
            score += 10
            reasons.add("Starts automatically on device boot (persistence)")
        }

        // 4. Context Mismatch Rule (e.g. Utility app requesting sensitive SMS/Contacts)
        val isUtility = appName.contains("torch", true) || appName.contains("calculator", true) || appName.contains("flashlight", true)
        if (isUtility && (hasSms || permissions.any { it.contains("CONTACTS", true) })) {
            score += 25
            reasons.add("Context Mismatch: Utility app requesting sensitive SMS/Contacts")
        }

        val finalScore = score.coerceIn(0, 100)
        val band = when {
            finalScore >= 75 -> "Critical"
            finalScore >= 50 -> "High"
            finalScore >= 25 -> "Medium"
            else -> "Low"
        }

        if (reasons.isEmpty()) {
            reasons.add("Standard application permissions with minimal risk footprint.")
        }

        return Triple(finalScore, band, reasons)
    }
}