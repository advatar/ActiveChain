package dev.activechain.wallet

data class NetworkProfile(val id: String, val displayName: String, val genesis: String,
                          val rpcUrl: String, val faucetUrl: String?, val assets: List<String>)

class NetworkSelection(profiles: List<NetworkProfile>, selectedId: String? = null, private val preferences: android.content.SharedPreferences? = null) {
    private val all = profiles.associateBy { it.id }
    var selected: NetworkProfile = all[selectedId ?: preferences?.getString("activechain.selected-network", null)] ?: profiles.first()
        private set
    val visibleAssets: List<String> get() = selected.assets
    fun switchTo(id: String): Boolean { val next = all[id] ?: return false; selected = next; preferences?.edit()?.putString("activechain.selected-network", id)?.apply(); return true }
}
