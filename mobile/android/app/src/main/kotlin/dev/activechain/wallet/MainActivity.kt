package dev.activechain.wallet

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

private object Palette {
    val ink = Color.rgb(9, 14, 23)
    val panel = Color.rgb(19, 27, 39)
    val mint = Color.rgb(115, 244, 181)
    val cyan = Color.rgb(87, 204, 240)
    val violet = Color.rgb(156, 137, 250)
    val muted = Color.rgb(159, 169, 184)
    val white = Color.rgb(246, 248, 252)
}

private enum class WalletTab(val label: String, val glyph: String) {
    WALLET("Wallet", "▣"),
    ACTIVITY("Activity", "↻"),
    APPROVALS("Approvals", "✓"),
    IDENTITY("Identity", "ID")
}

class MainActivity : Activity() {
    private lateinit var content: FrameLayout
    private lateinit var nav: LinearLayout
    private var selected = WalletTab.WALLET

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Palette.ink

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Palette.ink)
        }
        content = FrameLayout(this)
        nav = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(8))
            background = rounded(Palette.panel, 28, stroke = Color.argb(22, 255, 255, 255))
        }
        root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(nav, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(78)).apply {
            setMargins(dp(12), 0, dp(12), dp(10))
        })
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }
        setContentView(root)
        show(WalletTab.WALLET)
    }

    private fun show(tab: WalletTab) {
        selected = tab
        content.removeAllViews()
        content.addView(
            when (tab) {
                WalletTab.WALLET -> walletScreen()
                WalletTab.ACTIVITY -> activityScreen()
                WalletTab.APPROVALS -> approvalsScreen()
                WalletTab.IDENTITY -> identityScreen()
            },
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        )
        renderNavigation()
    }

    private fun renderNavigation() {
        nav.removeAllViews()
        WalletTab.entries.forEach { tab ->
            val active = tab == selected
            val button = TextView(this).apply {
                gravity = Gravity.CENTER
                text = if (tab == WalletTab.APPROVALS) "${tab.glyph}  2\n${tab.label}" else "${tab.glyph}\n${tab.label}"
                textSize = 12f
                setTextColor(if (active) Palette.mint else Palette.white)
                typeface = Typeface.create(Typeface.DEFAULT, if (active) Typeface.BOLD else Typeface.NORMAL)
                background = if (active) rounded(Color.rgb(48, 61, 80), 20) else null
                contentDescription = if (tab == WalletTab.APPROVALS) "Approvals, 2 pending" else tab.label
                setOnClickListener { show(tab) }
            }
            nav.addView(button, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f).apply {
                setMargins(dp(2), 0, dp(2), 0)
            })
        }
    }

    private fun walletScreen(): View = scrollColumn {
        addView(header())
        addView(balanceCard(), marginTop = 18)
        addView(networkCard(), marginTop = 14)
        addView(approvalBanner(), marginTop = 14)
        addView(sectionTitle("Assets", "Manage"), marginTop = 22)
        addView(assetRow("A", "ActiveChain", "ACT", "12,480.42", "$2,742.69", Palette.mint), marginTop = 10)
        addView(assetRow("€", "Test Euro", "tEUR", "240.00", "$281.35", Palette.cyan), marginTop = 10)
        addView(label("◆  Keys protected on this device · Post-quantum signing", 12, Palette.muted).apply {
            gravity = Gravity.CENTER
            setPadding(0, dp(24), 0, dp(22))
        })
    }

    private fun header(): View = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        addView(label("A", 22, Palette.ink, bold = true).apply {
            gravity = Gravity.CENTER
            background = rounded(Palette.mint, 40)
        }, LinearLayout.LayoutParams(dp(48), dp(48)))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, 0, 0)
            addView(label("Good morning", 14, Palette.muted))
            addView(label("Johan", 25, Palette.white, bold = true))
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(label("⌗", 24, Palette.mint, bold = true).apply {
            gravity = Gravity.CENTER
            background = rounded(Color.argb(20, 255, 255, 255), 40)
            contentDescription = "Scan QR code"
        }, LinearLayout.LayoutParams(dp(46), dp(46)))
    }

    private fun balanceCard(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(20))
        background = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(Color.rgb(27, 78, 69), Color.rgb(20, 40, 63), Color.rgb(42, 30, 71))
        ).apply {
            cornerRadius = dp(28).toFloat()
            setStroke(dp(1), Color.argb(28, 255, 255, 255))
        }
        addView(LinearLayout(context).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(label("✦  Total balance", 14, Color.rgb(205, 214, 220), bold = true),
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(label("TESTNET", 11, Palette.ink, bold = true).apply {
                gravity = Gravity.CENTER
                letterSpacing = .15f
                background = rounded(Palette.mint, 18)
                setPadding(dp(12), dp(7), dp(12), dp(7))
            })
        })
        addView(label("12,480.42 ACT", 34, Palette.white, bold = true).apply {
            setPadding(0, dp(20), 0, 0)
        })
        addView(label("≈ 2,742.69 USD", 15, Color.rgb(184, 195, 205)).apply {
            setPadding(0, dp(3), 0, dp(19))
        })
        addView(LinearLayout(context).apply {
            gravity = Gravity.CENTER
            addView(actionButton("↗", "Send", true) { showSend() }, weighted())
            addView(actionButton("↙", "Receive", false) { toast("Receive address ready") }, weighted(8))
            addView(actionButton("+", "Fund", false) { toast("Development faucet") }, weighted(8))
        })
    }

    private fun networkCard(): View = rowCard(
        leading = badge("●", Palette.cyan),
        title = "Kanalen",
        subtitle = "Finalized block 184,291 · 3 validators",
        trailing = "Healthy\n2s ago",
        trailingColor = Palette.mint
    ).apply { contentDescription = "Kanalen testnet healthy, finalized block 184291, three validators" }

    private fun approvalBanner(): View = rowCard(
        leading = badge("✦", Palette.violet),
        title = "2 agent actions need you",
        subtitle = "Review scope, recipient and exact fee",
        trailing = "›",
        trailingColor = Palette.muted
    ).apply {
        isClickable = true
        setOnClickListener { show(WalletTab.APPROVALS) }
    }

    private fun assetRow(
        glyph: String, title: String, symbol: String, amount: String, value: String, color: Int
    ) = rowCard(
        leading = badge(glyph, color, darkText = true),
        title = title,
        subtitle = symbol,
        trailing = "$amount\n$value",
        trailingColor = Palette.white
    )

    private fun activityScreen(): View = scrollColumn {
        addView(screenTitle("Activity", "Finalized wallet events"))
        val entries = listOf(
            arrayOf("↙", "Received ACT", "Faucet · finalized", "+ 2,500.00 ACT"),
            arrayOf("↗", "Sent to did:…7f2c", "Block 184,102", "− 42.00 ACT"),
            arrayOf("✓", "Agent settlement", "Research agent · verified", "− 1.20 ACT"),
            arrayOf("ID", "Credential received", "Kanalen Test ID", "OpenWallet")
        )
        entries.forEachIndexed { index, item ->
            val color = listOf(Palette.mint, Palette.white, Palette.violet, Palette.cyan)[index]
            addView(rowCard(badge(item[0], color), item[1], item[2], item[3], color), marginTop = 12)
        }
    }

    private fun approvalsScreen(): View = scrollColumn {
        addView(screenTitle("Approvals", "Exact, consent-bound actions"))
        addView(approvalCard("Research agent", "Pay data provider", "18.00 ACT + 0.08 fee", "Within daily limit", Palette.mint), marginTop = 12)
        addView(approvalCard("Travel planner", "Share identity credential", "Name · age over 18 · nationality", "3 claims requested", Palette.violet), marginTop = 14)
        addView(label("Every approval is bound to the exact action, recipient, fee, claims and expiry.", 12, Palette.muted).apply {
            gravity = Gravity.CENTER
            setPadding(dp(20), dp(22), dp(20), dp(20))
        })
    }

    private fun identityScreen(): View = scrollColumn {
        addView(screenTitle("Identity", "OpenWallet credentials"))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(18), dp(24), dp(18), dp(24))
            background = rounded(Palette.panel, 22, stroke = Color.argb(18, 255, 255, 255))
            addView(label("◉", 48, Palette.mint, bold = true))
            addView(label("Johan’s wallet", 23, Palette.white, bold = true).apply { setPadding(0, dp(8), 0, 0) })
            addView(label("did:activechain:kanalen:8c7a…19ef", 12, Palette.muted).apply { setPadding(0, dp(5), 0, 0) })
            addView(label("◆  Device protected", 12, Palette.mint, bold = true).apply { setPadding(0, dp(10), 0, 0) })
        }, marginTop = 12)
        addView(sectionTitle("Credentials", ""), marginTop = 22)
        addView(rowCard(badge("ID", Palette.cyan), "Kanalen Test ID", "ActiveChain Foundation", "›", Palette.muted), marginTop = 10)
        addView(rowCard(badge("18", Palette.violet), "Age over 18", "Derived disclosure", "›", Palette.muted), marginTop = 10)
        addView(Button(context).apply {
            text = "Add credential"
            textSize = 16f
            setTextColor(Palette.ink)
            typeface = Typeface.DEFAULT_BOLD
            background = rounded(Palette.mint, 16)
            setOnClickListener { toast("Scan an OpenWallet credential offer") }
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(54)), marginTop = 18)
    }

    private fun showSend() {
        val sheet = android.app.Dialog(this).apply {
            window?.setBackgroundDrawableResource(android.R.color.transparent)
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(22), dp(22), dp(22))
            background = rounded(Palette.panel, 26, stroke = Color.argb(24, 255, 255, 255))
        }
        body.addView(label("Send ACT", 25, Palette.white, bold = true))
        body.addView(label("Exact recipient, fee and validity are shown before signing.", 13, Palette.muted).apply {
            setPadding(0, dp(5), 0, dp(18))
        })
        val amount = input("Amount in ACT", "42")
        val recipient = input("Recipient DID", "did:activechain:kanalen:")
        body.addView(amount, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(58)))
        body.addView(recipient, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(58)).apply {
            setMargins(0, dp(12), 0, 0)
        })
        body.addView(label("Fee reserve                                      0.08 ACT", 14, Palette.white).apply {
            setPadding(dp(4), dp(18), dp(4), dp(18))
        })
        body.addView(Button(this).apply {
            text = "Review and approve"
            textSize = 16f
            setTextColor(Palette.ink)
            typeface = Typeface.DEFAULT_BOLD
            background = rounded(Palette.mint, 16)
            setOnClickListener {
                val value = amount.text.toString().toLongOrNull() ?: 0
                val preview = LocalWalletBridge().previewTransfer(recipient.text.toString(), value, 1, 184391, 184291)
                if (preview.policyAllowed) {
                    LocalWalletBridge().approveTransfer(preview)
                    toast("Canonical intent approved")
                    sheet.dismiss()
                } else {
                    amount.error = "Enter an allowed amount"
                }
            }
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(54)))
        sheet.setContentView(body, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        sheet.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        sheet.show()
        sheet.window?.setLayout((resources.displayMetrics.widthPixels * .92).toInt(), ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun approvalCard(agent: String, action: String, detail: String, risk: String, color: Int) =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = rounded(Palette.panel, 22, stroke = Color.argb(55, Color.red(color), Color.green(color), Color.blue(color)))
            addView(label("✦  $agent", 13, color, bold = true))
            addView(label(action, 20, Palette.white, bold = true).apply { setPadding(0, dp(14), 0, 0) })
            addView(label(detail, 14, Palette.muted).apply { setPadding(0, dp(4), 0, 0) })
            addView(label("●  $risk", 12, Palette.mint, bold = true).apply { setPadding(0, dp(13), 0, dp(16)) })
            addView(LinearLayout(context).apply {
                addView(Button(context).apply {
                    text = "Decline"; setTextColor(Palette.white); background = rounded(Color.rgb(42, 50, 64), 15)
                }, weighted())
                addView(Button(context).apply {
                    text = "Review"; setTextColor(Palette.ink); typeface = Typeface.DEFAULT_BOLD
                    background = rounded(Palette.mint, 15)
                }, weighted(10))
            })
        }

    private fun rowCard(leading: View, title: String, subtitle: String, trailing: String, trailingColor: Int) =
        LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(15), dp(15), dp(15), dp(15))
            background = rounded(Palette.panel, 20, stroke = Color.argb(18, 255, 255, 255))
            addView(leading, LinearLayout.LayoutParams(dp(44), dp(44)))
            addView(LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(13), 0, dp(8), 0)
                addView(label(title, 15, Palette.white, bold = true))
                addView(label(subtitle, 12, Palette.muted).apply { setPadding(0, dp(3), 0, 0) })
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(label(trailing, 12, trailingColor, bold = true).apply {
                gravity = Gravity.END
            })
        }

    private fun badge(text: String, color: Int, darkText: Boolean = false) = label(
        text, if (text.length > 1) 12 else 18, if (darkText) Palette.ink else color, bold = true
    ).apply {
        gravity = Gravity.CENTER
        background = rounded(if (darkText) color else Color.argb(32, Color.red(color), Color.green(color), Color.blue(color)), 22)
    }

    private fun actionButton(icon: String, title: String, emphasized: Boolean, onClick: () -> Unit) =
        TextView(this).apply {
            text = "$icon\n$title"
            textSize = 13f
            gravity = Gravity.CENTER
            setTextColor(if (emphasized) Palette.ink else Palette.white)
            typeface = Typeface.DEFAULT_BOLD
            background = rounded(if (emphasized) Palette.mint else Color.argb(22, 255, 255, 255), 17)
            setOnClickListener { onClick() }
            contentDescription = title
        }

    private fun screenTitle(title: String, subtitle: String) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(label(title, 30, Palette.white, bold = true))
        addView(label(subtitle, 14, Palette.muted).apply { setPadding(0, dp(3), 0, 0) })
    }

    private fun sectionTitle(title: String, action: String) = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        addView(label(title, 21, Palette.white, bold = true), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (action.isNotEmpty()) addView(label(action, 14, Palette.mint, bold = true))
    }

    private fun scrollColumn(build: LinearLayout.() -> Unit): View = ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(22))
            build()
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun LinearLayout.addView(view: View, marginTop: Int) {
        addView(view, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            setMargins(0, dp(marginTop), 0, 0)
        })
    }

    private fun LinearLayout.addView(view: View, params: ViewGroup.LayoutParams, marginTop: Int) {
        val layout = LinearLayout.LayoutParams(params.width, params.height).apply { setMargins(0, dp(marginTop), 0, 0) }
        addView(view, layout)
    }

    private fun label(text: String, size: Int, color: Int, bold: Boolean = false) = TextView(this).apply {
        this.text = text
        textSize = size.toFloat()
        setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
    }

    private fun input(hint: String, value: String) = EditText(this).apply {
        this.hint = hint
        setHintTextColor(Palette.muted)
        setText(value)
        setTextColor(Palette.white)
        textSize = 15f
        setPadding(dp(14), 0, dp(14), 0)
        background = rounded(Color.rgb(37, 46, 60), 15)
        setSingleLine(true)
    }

    private fun rounded(color: Int, radius: Int, stroke: Int? = null) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
        stroke?.let { setStroke(dp(1), it) }
    }

    private fun weighted(gap: Int = 0) = LinearLayout.LayoutParams(0, dp(62), 1f).apply {
        if (gap > 0) setMargins(dp(gap), 0, 0, 0)
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}
