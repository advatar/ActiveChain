import SwiftUI

private final class IdentityNoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

@MainActor
final class IdentityConnection: ObservableObject {
    private struct Record: Codable {
        var session: IdentityTestSession
        var receipt: IdentityTestReceipt?
    }
    @Published private(set) var busy = false
    @Published private(set) var message = "Share an age-over-18 test claim from EUWallet."
    @Published private(set) var proof: String?
    @Published private(set) var pending = false
    private var record: Record?
    private var owner = ""
    private var chain = ""
    private var account = ""

    func select(owner: Data, chain: Data) {
        let newOwner = owner.map { String(format: "%02x", $0) }.joined()
        let newChain = chain.map { String(format: "%02x", $0) }.joined()
        guard newOwner != self.owner || newChain != self.chain else { return }
        self.owner = newOwner; self.chain = newChain
        account = newOwner + "." + newChain
        record = nil; proof = nil; pending = false
        message = "Share an age-over-18 test claim from EUWallet."
        do {
            if let data = try SharedKeychain().load(service: "dev.activechain.identity-test.v1", account: account) {
                let stored = try JSONDecoder().decode(Record.self, from: data)
                if let receipt = stored.receipt {
                    try receipt.validate(session: stored.session, owner: newOwner, chain: newChain)
                }
                record = stored
                display()
            }
        } catch { message = "The saved test connection could not be loaded." }
    }

    func start() async -> URL? {
        guard !busy, !owner.isEmpty else { return nil }
        busy = true
        defer { busy = false }
        let originalAccount = account
        do {
            var request = URLRequest(url: URL(string: IdentityTestSession.base + "/sessions")!)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["owner": owner, "chain": chain])
            let session = try JSONDecoder().decode(IdentityTestSession.self, from: await fetch(request))
            try session.validate()
            guard originalAccount == account else { return nil }
            let next = Record(session: session)
            try save(next)
            record = next; proof = nil; pending = true
            message = "Waiting for your consent in EUWallet. Return here to check the result."
            return session.invocation
        } catch {
            message = "Could not start the EUWallet test connection. Check your connection and try again."
            return nil
        }
    }

    func returned(_ url: URL) async {
        guard record?.session.matchesReturn(url) == true else { return }
        await refresh()
    }

    func refresh() async {
        guard !busy, var current = record, current.receipt?.status != "test_verified" else { return }
        busy = true
        defer { busy = false }
        let originalAccount = account
        do {
            var request = URLRequest(url: URL(string: IdentityTestSession.base + "/status/" + current.session.id)!)
            request.setValue("Bearer " + current.session.token, forHTTPHeaderField: "Authorization")
            let receipt = try JSONDecoder().decode(IdentityTestReceipt.self, from: await fetch(request))
            guard originalAccount == account else { return }
            try receipt.validate(session: current.session, owner: owner, chain: chain)
            current.receipt = receipt
            try save(current)
            record = current
            display()
        } catch { message = "Could not check the result. Your test connection is saved; try again." }
    }

    func openingFailed() { message = "EUWallet could not be opened. Install its test build, then try again." }
    private func save(_ value: Record) throws {
        try SharedKeychain().save(JSONEncoder().encode(value), service: "dev.activechain.identity-test.v1", account: account)
    }
    private func display() {
        proof = record?.receipt?.status == "test_verified" ? record?.receipt?.proof : nil
        pending = record != nil && (record?.receipt == nil || record?.receipt?.status == "pending")
        switch record?.receipt?.status {
        case "test_verified": message = "Test credential attached. EUWallet’s issuer signature and holder proof passed."
        case "declined": message = "Sharing was declined in EUWallet. You can try again."
        case "rejected": message = "The received proof did not pass the test checks. No credential was attached."
        case "expired": message = "The test request expired. Start a new connection."
        default: message = "Waiting for EUWallet. Check the result after giving consent."
        }
    }
    private func fetch(_ request: URLRequest) async throws -> Data {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        let session = URLSession(configuration: config, delegate: IdentityNoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              http.url?.host == "kanalen.actum.network", data.count < 16384 else {
            throw IdentityTestError.invalidResponse
        }
        return data
    }
}

struct IdentityConnectionCard: View {
    @ObservedObject var connection: IdentityConnection
    @Environment(\.openURL) private var openURL
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Composite identity credentials", systemImage: "person.text.rectangle").font(.headline)
            Text("EUWallet test connection").font(.subheadline.bold())
            Text("Use the EUWallet test build with a sample PID credential. You approve sharing in EUWallet; your holder key stays there.")
                .font(.caption).foregroundStyle(WalletPalette.muted)
            Label("TEST ONLY · No government verification", systemImage: "flask.fill")
                .font(.caption.bold()).foregroundStyle(.orange)
            Text(connection.message).font(.subheadline).accessibilityIdentifier("identity.connection.status")
            if let proof = connection.proof {
                Text("Receipt " + String(proof.prefix(16))).font(.caption.monospaced())
                Text("Saved on this device. External trust and on-chain identity registration are deferred.")
                    .font(.caption).foregroundStyle(WalletPalette.muted)
            }
            Button(connection.busy ? "Connecting…" : "Use EUWallet") {
                Task {
                    if let url = await connection.start() {
                        openURL(url) { accepted in
                            if !accepted { connection.openingFailed() }
                        }
                    }
                }
            }.buttonStyle(.borderedProminent).disabled(connection.busy)
                .accessibilityIdentifier("identity.connect.euwallet")
            if connection.pending {
                Button("Check result") { Task { await connection.refresh() } }
                    .disabled(connection.busy).accessibilityIdentifier("identity.connection.check")
            }
        }.frame(maxWidth: .infinity, alignment: .leading).cardStyle()
    }
}
