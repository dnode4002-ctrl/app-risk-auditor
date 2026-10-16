package com.audit.risk

data class AppModel(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val installDate: Long,
    val isSystemApp: Boolean,
    val installerSource: String,
    val targetSdk: Int,
    val grantedPermissions: List<String>,
    val riskScore: Int,
    val riskBand: String,
    val riskReasons: List<String>
)