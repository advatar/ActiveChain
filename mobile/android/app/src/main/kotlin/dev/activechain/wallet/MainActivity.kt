package dev.activechain.wallet

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val bridge = LocalWalletBridge()
        val preview = bridge.previewTransfer("did:activechain:test", 10, 2, 100, 1)
        val status = TextView(this).apply { text = "Review transfer: ${preview.amount} ACT\nPolicy: ${preview.policyAllowed}"; textSize = 18f; setPadding(32, 48, 32, 32) }
        val approve = Button(this).apply { text = "Preview and approve"; setOnClickListener { text = "Approved local intent" } }
        setContentView(LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(status); addView(approve) })
    }
}
