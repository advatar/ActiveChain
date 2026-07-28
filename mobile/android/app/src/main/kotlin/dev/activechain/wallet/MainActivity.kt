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
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import java.io.File

private object Palette {
    val ink = Color.rgb(9, 14, 23)
    val panel = Color.rgb(19, 27, 39)
    val mint = Color.rgb(115, 244, 181)
    val cyan = Color.rgb(87, 204, 240)
    val violet = Color.rgb(156, 137, 250)
    val muted = Color.rgb(159, 169, 184)
    val warning = Color.rgb(255, 177, 82)
    val danger = Color.rgb(255, 96, 110)
    val white = Color.rgb(246, 248, 252)
}

private enum class WalletTab(val label: String, val glyph: String) {
    WALLET("Wallet", "▣"),
    ACTIVITY("Activity", "↻"),
    APPROVALS("Approvals", "✓"),
    IDENTITY("Identity", "ID"),
}

class MainActivity : Activity() {
    private lateinit var content: FrameLayout
    private lateinit var nav: LinearLayout
    private lateinit var agents: RustAgentRegistry
    private var selected = WalletTab.WALLET
    private var networkState: KanalenNetworkState = KanalenNetworkState.Checking
    private var refreshGeneration = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Palette.ink
        agents = RustAgentRegistry(File(filesDir, "agents-v1.bin"))

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Palette.ink)
        }
        content = FrameLayout(this)
        nav = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(8))
            background = rounded(Palette.panel, 28, Color.argb(22, 255, 255, 255))
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
        refreshNetworkStatus()
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
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ),
        )
        renderNavigation()
    }

    private fun renderNavigation() {
        nav.removeAllViews()
        WalletTab.entries.forEach { tab ->
            val active = tab == selected
            val button = TextView(this).apply {
                gravity = Gravity.CENTER
                text = "${tab.glyph}\n${tab.label}"
                textSize = 12f
                setTextColor(if (active) Palette.mint else Palette.white)
                typeface = Typeface.create(Typeface.DEFAULT, if (active) Typeface.BOLD else Typeface.NORMAL)
                background = if (active) rounded(Color.rgb(48, 61, 80), 20) else null
                contentDescription = tab.label
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
        addView(sectionTitle("Assets"), marginTop = 22)
        addView(
            emptyState(
                "No verified assets",
                "Balances require a real wallet profile and finalized owner-scoped Coin Cell proofs.",
            ),
            marginTop = 10,
        )
        addView(label("◆  No signing key is loaded on this device", 12, Palette.muted).apply {
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
            addView(label("ActiveChain", 14, Palette.muted))
            addView(label("Wallet", 25, Palette.white, bold = true))
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    }

    private fun balanceCard(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(20))
        background = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(Color.rgb(27, 78, 69), Color.rgb(20, 40, 63), Color.rgb(42, 30, 71)),
        ).apply {
            cornerRadius = dp(28).toFloat()
            setStroke(dp(1), Color.argb(28, 255, 255, 255))
        }
        addView(LinearLayout(context).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(
                label("✦  Total balance", 14, Color.rgb(205, 214, 220), bold = true),
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
            addView(label("TESTNET", 11, Palette.ink, bold = true).apply {
                gravity = Gravity.CENTER
                letterSpacing = .15f
                background = rounded(Palette.mint, 18)
                setPadding(dp(12), dp(7), dp(12), dp(7))
            })
        })
        addView(label("Balance unavailable", 30, Palette.white, bold = true).apply {
            setPadding(0, dp(20), 0, 0)
        })
        addView(label(
            "Android owner-state verification is not connected; no local or optimistic balance is shown.",
            13,
            Color.rgb(184, 195, 205),
        ).apply { setPadding(0, dp(5), 0, dp(19)) })
        addView(LinearLayout(context).apply {
            gravity = Gravity.CENTER
            addView(actionButton("↗", "Send"), weighted())
            addView(actionButton("↙", "Receive"), weighted(8))
            addView(actionButton("+", "Fund"), weighted(8))
        })
        addView(label(
            "Transfers and funding remain disabled until finalized state, secure signing, and validator ingress are wired.",
            11,
            Palette.warning,
            bold = true,
        ).apply { setPadding(0, dp(14), 0, 0) })
    }

    private fun networkCard(): View {
        val presentation = when (val state = networkState) {
            KanalenNetworkState.Checking -> Triple("Querying canonical TLS status", "Checking", Palette.warning)
            is KanalenNetworkState.Healthy -> Triple(
                "Finalized block ${state.finalizedHeight}",
                "Healthy",
                Palette.mint,
            )
            is KanalenNetworkState.Stale -> Triple(
                "Finalized block ${state.finalizedHeight} has not advanced recently",
                "Stale",
                Palette.warning,
            )
            KanalenNetworkState.Unavailable -> Triple(
                "TLS RPC status request failed",
                "Unavailable",
                Palette.danger,
            )
            KanalenNetworkState.Incompatible -> Triple(
                "Unexpected chain, genesis, protocol, or RPC schema",
                "Incompatible",
                Palette.danger,
            )
        }
        return rowCard(
            badge("●", Palette.cyan),
            "Kanalen",
            presentation.first,
            presentation.second,
            presentation.third,
        ).apply {
            isClickable = true
            contentDescription = "Kanalen testnet, ${presentation.second}, ${presentation.first}"
            setOnClickListener { refreshNetworkStatus() }
        }
    }

    private fun refreshNetworkStatus() {
        refreshGeneration += 1
        val generation = refreshGeneration
        networkState = KanalenNetworkState.Checking
        if (selected == WalletTab.WALLET) show(WalletTab.WALLET)
        Thread {
            val next = try {
                KanalenRPCClient().status().networkState()
            } catch (_: Exception) {
                KanalenNetworkState.Unavailable
            }
            runOnUiThread {
                if (!isDestroyed && generation == refreshGeneration) {
                    networkState = next
                    if (selected == WalletTab.WALLET) show(WalletTab.WALLET)
                }
            }
        }.start()
    }

    private fun activityScreen(): View = scrollColumn {
        addView(screenTitle("Activity", "Finalized wallet events only"))
        addView(
            emptyState(
                "No verified activity",
                "Activity will appear after finalized receipt queries are connected.",
            ),
            marginTop = 14,
        )
    }

    private fun approvalsScreen(): View = scrollColumn {
        addView(screenTitle("Approvals", "Exact, consent-bound actions only"))
        addView(rowCard(
            badge("⚙", Palette.mint),
            "Manage agents",
            if (agents.agents.isEmpty()) "No registered agents" else "${agents.agents.size} persisted agents",
            "›",
            Palette.muted,
        ).apply {
            isClickable = true
            contentDescription = "Manage agents"
            setOnClickListener { showAgentManager() }
        }, marginTop = 12)
        addView(
            emptyState(
                "No pending approvals",
                "Only persisted approval-bound requests will be shown here.",
            ),
            marginTop = 14,
        )
    }

    private fun showAgentManager() {
        val dialog = android.app.Dialog(this)
        val body = scrollColumn {
            addView(screenTitle("Agents", "Persisted ActiveChain authority controls"))
            addView(label(
                "Agents are authenticated principals. These controls limit only their ActiveChain authority.",
                12,
                Palette.muted,
            ).apply {
                setPadding(dp(15), dp(15), dp(15), dp(15))
                background = rounded(Color.argb(28, 156, 137, 250), 18)
            }, marginTop = 14)
            if (agents.agents.isEmpty()) {
                addView(
                    emptyState(
                        "No registered agents",
                        "This wallet does not create development agents or sample authority.",
                    ),
                    marginTop = 14,
                )
            }
            agents.agents.forEach { agent ->
                addView(agentManagementCard(agent) { dialog.dismiss(); showAgentManager() }, marginTop = 14)
            }
            addView(Button(context).apply {
                text = "Done"
                minimumHeight = dp(54)
                setTextColor(Palette.ink)
                typeface = Typeface.DEFAULT_BOLD
                background = rounded(Palette.mint, 16)
                setOnClickListener { dialog.dismiss() }
            }, marginTop = 18)
        }
        dialog.setContentView(body)
        dialog.show()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * .94).toInt(),
            (resources.displayMetrics.heightPixels * .88).toInt(),
        )
    }

    private fun agentManagementCard(agent: AgentDelegation, refresh: () -> Unit): View =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = rounded(Palette.panel, 22, Color.argb(28, 255, 255, 255))
            val status = when (val lifecycle = agent.lifecycle) {
                AgentLifecycle.Active -> "Active"
                AgentLifecycle.Paused -> "Paused"
                AgentLifecycle.RevocationPending -> "Revocation pending"
                is AgentLifecycle.Revoked -> "Revoked at block ${lifecycle.finalizedHeight}"
            }
            val statusColor = when (agent.lifecycle) {
                AgentLifecycle.Active -> Palette.mint
                AgentLifecycle.Paused -> Palette.warning
                AgentLifecycle.RevocationPending -> Palette.violet
                is AgentLifecycle.Revoked -> Palette.danger
            }
            addView(label("✦  ${agent.label}", 17, Palette.white, bold = true))
            addView(label("${agent.connection.label} · $status", 12, statusColor, bold = true).apply {
                setPadding(0, dp(5), 0, 0)
            })
            addView(label(agent.id, 11, Palette.muted).apply { setPadding(0, dp(6), 0, 0) })
            addView(label(
                "${agent.capabilities.joinToString(" · ")}\nBudget ${agent.spentToday}/${agent.dailyLimit} ACT",
                12,
                Palette.muted,
            ).apply { setPadding(0, dp(12), 0, dp(14)) })
            if (agent.lifecycle == AgentLifecycle.Active || agent.lifecycle == AgentLifecycle.Paused) {
                addView(LinearLayout(context).apply {
                    addView(Button(context).apply {
                        text = if (agent.lifecycle == AgentLifecycle.Active) "Pause" else "Resume"
                        setTextColor(Palette.white)
                        background = rounded(Color.rgb(42, 50, 64), 15)
                        setOnClickListener {
                            if (agent.lifecycle == AgentLifecycle.Active) agents.pause(agent.id) else agents.resume(agent.id)
                            refresh()
                        }
                    }, weighted())
                    addView(Button(context).apply {
                        text = "Revoke"
                        setTextColor(Palette.ink)
                        typeface = Typeface.DEFAULT_BOLD
                        background = rounded(Palette.danger, 15)
                        setOnClickListener { agents.revoke(agent.id); refresh() }
                    }, weighted(10))
                })
            }
        }

    private fun identityScreen(): View = scrollColumn {
        addView(screenTitle("Identity", "OpenWallet credentials"))
        addView(
            emptyState(
                "No wallet identity",
                "Create or import a real wallet profile before receiving credentials or funds.",
            ),
            marginTop = 14,
        )
        addView(
            emptyState(
                "No credentials",
                "Only credentials persisted through the OpenWallet boundary will appear.",
            ),
            marginTop = 14,
        )
    }

    private fun emptyState(title: String, detail: String): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        setPadding(dp(20), dp(24), dp(20), dp(24))
        background = rounded(Palette.panel, 20, Color.argb(18, 255, 255, 255))
        addView(label("◇", 30, Palette.muted, bold = true))
        addView(label(title, 18, Palette.white, bold = true).apply { setPadding(0, dp(9), 0, 0) })
        addView(label(detail, 12, Palette.muted).apply {
            gravity = Gravity.CENTER
            setPadding(0, dp(6), 0, 0)
        })
    }

    private fun rowCard(
        leading: View,
        title: String,
        subtitle: String,
        trailing: String,
        trailingColor: Int,
    ) = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(15), dp(15), dp(15), dp(15))
        background = rounded(Palette.panel, 20, Color.argb(18, 255, 255, 255))
        addView(leading, LinearLayout.LayoutParams(dp(44), dp(44)))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(13), 0, dp(8), 0)
            addView(label(title, 15, Palette.white, bold = true))
            addView(label(subtitle, 12, Palette.muted).apply { setPadding(0, dp(3), 0, 0) })
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(label(trailing, 12, trailingColor, bold = true).apply { gravity = Gravity.END })
    }

    private fun badge(text: String, color: Int) = label(text, 18, color, bold = true).apply {
        gravity = Gravity.CENTER
        background = rounded(Color.argb(32, Color.red(color), Color.green(color), Color.blue(color)), 22)
    }

    private fun actionButton(icon: String, title: String) = TextView(this).apply {
        text = "$icon\n$title"
        textSize = 13f
        gravity = Gravity.CENTER
        setTextColor(Palette.muted)
        typeface = Typeface.DEFAULT_BOLD
        background = rounded(Color.argb(15, 255, 255, 255), 17)
        isEnabled = false
        alpha = .65f
        contentDescription = "$title unavailable"
    }

    private fun screenTitle(title: String, subtitle: String) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(label(title, 30, Palette.white, bold = true))
        addView(label(subtitle, 14, Palette.muted).apply { setPadding(0, dp(3), 0, 0) })
    }

    private fun sectionTitle(title: String) = label(title, 21, Palette.white, bold = true)

    private fun scrollColumn(build: LinearLayout.() -> Unit): ScrollView = ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(22))
            build()
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun LinearLayout.addView(view: View, marginTop: Int) {
        addView(view, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(0, dp(marginTop), 0, 0) })
    }

    private fun label(text: String, size: Int, color: Int, bold: Boolean = false) = TextView(this).apply {
        this.text = text
        textSize = size.toFloat()
        setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
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
}
