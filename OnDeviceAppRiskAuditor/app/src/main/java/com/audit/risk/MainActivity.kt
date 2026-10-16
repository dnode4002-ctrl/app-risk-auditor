package com.audit.risk

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var listView: ListView
    private lateinit var tvSummary: TextView
    private var includeSystemApps = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        tvSummary = TextView(this).apply {
            textSize = 16f
            setTextColor(android.graphics.Color.WHITE)
            setPadding(0, 0, 0, 24)
        }
        layout.addView(tvSummary)

        val btnToggle = Button(this).apply {
            text = "Toggle System Apps (Off)"
            setOnClickListener {
                includeSystemApps = !includeSystemApps
                text = "System Apps: ${if (includeSystemApps) "Shown" else "Hidden"}"
                loadAppAudit()
            }
        }
        layout.addView(btnToggle)

        listView = ListView(this)
        layout.addView(listView)

        setContentView(layout)
        loadAppAudit()
    }

    private fun loadAppAudit() {
        val apps = RiskAnalyzer.getInstalledApps(this, includeSystemApps)
        val criticalCount = apps.count { it.riskBand == "Critical" || it.riskBand == "High" }
        
        tvSummary.text = "Scanned ${apps.size} apps.\n⚠️ Flagged High/Critical: $criticalCount apps.\nTap any app for details, remediation, or uninstallation."

        val displayList = apps.map { "${it.appName} [${it.riskBand.uppercase()}] - Score: ${it.riskScore}/100\nReasons: ${it.riskReasons.first()}" }
        
        val adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, displayList)
        listView.adapter = adapter

        listView.setOnItemClickListener { _, _, position, _ ->
            val selectedApp = apps[position]
            showDetailDialog(selectedApp)
        }
    }

    private fun showDetailDialog(app: AppModel) {
        val message = buildString {
            append("Package: ${app.packageName}\n")
            append("Version: ${app.versionName}\n")
            append("Installer Source: ${app.installerSource}\n")
            append("Risk Score: ${app.riskScore}/100 (${app.riskBand})\n\n")
            append("Human-Readable Reasons:\n")
            app.riskReasons.forEach { append("• $it\n") }
        }

        AlertDialog.Builder(this)
            .setTitle(app.appName)
            .setMessage(message)
            .setPositiveButton("App Settings") { _, _ ->
                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:${app.packageName}")
                }
                startActivity(intent)
            }
            .setNeutralButton("Uninstall") { _, _ ->
                val intent = Intent(Intent.ACTION_DELETE).apply {
                    data = Uri.parse("package:${app.packageName}")
                }
                startActivity(intent)
            }
            .setNegativeButton("Close", null)
            .show()
    }
}