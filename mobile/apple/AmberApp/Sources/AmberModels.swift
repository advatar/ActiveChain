import Foundation

struct AmberBoardID: Hashable, Codable, Sendable, CustomStringConvertible {
    let slug: String

    init(_ slug: String) throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789")
        guard (1...12).contains(slug.count),
              slug.unicodeScalars.allSatisfy(allowed.contains)
        else {
            throw AmberModelError.invalidBoardID
        }
        self.slug = slug
    }

    var description: String { "/\(slug)/" }
}

struct AmberPostID: Hashable, Codable, Sendable, Comparable {
    let board: AmberBoardID
    let threadNumber: UInt64
    let postNumber: UInt32

    static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.threadNumber, lhs.postNumber) < (rhs.threadNumber, rhs.postNumber)
    }
}

struct AmberPost: Identifiable, Hashable, Sendable {
    let id: AmberPostID
    let authorLabel: String
    let body: String
    let createdAt: Date
    let image: AmberImage?

    init(
        id: AmberPostID,
        authorLabel: String = "Anonymous",
        body: String,
        createdAt: Date,
        image: AmberImage? = nil
    ) throws {
        guard body.utf8.count <= AmberLimits.maximumPostBytes else {
            throw AmberModelError.postTooLarge
        }
        self.id = id
        self.authorLabel = authorLabel
        self.body = body
        self.createdAt = createdAt
        self.image = image
    }
}

struct AmberImage: Hashable, Sendable {
    let digest: String
    let width: Int
    let height: Int
    let byteCount: Int

    init(digest: String, width: Int, height: Int, byteCount: Int) throws {
        guard digest.count == 64,
              digest.allSatisfy(\.isHexDigit),
              width > 0,
              height > 0,
              (1...AmberLimits.maximumImageBytes).contains(byteCount)
        else {
            throw AmberModelError.invalidImage
        }
        self.digest = digest.lowercased()
        self.width = width
        self.height = height
        self.byteCount = byteCount
    }
}

struct AmberThread: Identifiable, Hashable, Sendable {
    let board: AmberBoardID
    let number: UInt64
    let generation: UInt32
    let subject: String
    private(set) var posts: [AmberPost]

    var id: AmberPostID {
        AmberPostID(board: board, threadNumber: number, postNumber: 0)
    }

    init(
        board: AmberBoardID,
        number: UInt64,
        generation: UInt32,
        subject: String,
        posts: [AmberPost]
    ) throws {
        guard !posts.isEmpty, posts.count <= AmberLimits.maximumPostsPerThread else {
            throw AmberModelError.invalidPostCount
        }
        guard posts.allSatisfy({ $0.id.board == board && $0.id.threadNumber == number }) else {
            throw AmberModelError.mismatchedPost
        }
        let ordered = posts.sorted { $0.id < $1.id }
        guard Set(ordered.map(\.id)).count == ordered.count else {
            throw AmberModelError.duplicatePost
        }
        self.board = board
        self.number = number
        self.generation = generation
        self.subject = subject
        self.posts = ordered
    }
}

struct AmberBoard: Identifiable, Hashable, Sendable {
    let id: AmberBoardID
    let title: String
    let summary: String
    let activeUsers: Int
    let threads: [AmberThread]

    init(
        id: AmberBoardID,
        title: String,
        summary: String,
        activeUsers: Int,
        threads: [AmberThread]
    ) throws {
        guard activeUsers >= 0, threads.count <= AmberLimits.maximumActiveThreads else {
            throw AmberModelError.invalidBoard
        }
        guard threads.allSatisfy({ $0.board == id }),
              Set(threads.map(\.number)).count == threads.count
        else {
            throw AmberModelError.invalidBoard
        }
        self.id = id
        self.title = title
        self.summary = summary
        self.activeUsers = activeUsers
        self.threads = threads.sorted { $0.number > $1.number }
    }
}

enum AmberLimits {
    static let maximumActiveThreads = 128
    static let maximumPostsPerThread = 256
    static let maximumPostBytes = 8_192
    static let maximumImageBytes = 8 * 1_024 * 1_024
}

enum AmberModelError: Error, Equatable {
    case invalidBoardID
    case postTooLarge
    case invalidImage
    case invalidPostCount
    case mismatchedPost
    case duplicatePost
    case invalidBoard
}

enum AmberComposerReadiness: Equatable, Sendable {
    case chooseBoard
    case enterPost
    case acknowledgeBond
    case liveSubmissionUnavailable
    case ready

    static func evaluate(
        board: AmberBoardID?,
        body: String,
        understandsBond: Bool,
        liveSubmissionAvailable: Bool
    ) -> Self {
        guard board != nil else { return .chooseBoard }
        guard !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .enterPost
        }
        guard understandsBond else { return .acknowledgeBond }
        guard liveSubmissionAvailable else { return .liveSubmissionUnavailable }
        return .ready
    }

    var message: String {
        switch self {
        case .chooseBoard: "Choose a board to continue."
        case .enterPost: "Enter the post text to continue."
        case .acknowledgeBond: "Acknowledge the bond and moderation conditions to continue."
        case .liveSubmissionUnavailable:
            "Live posting is not connected yet; Amber will not pretend that a preview was submitted."
        case .ready: "Ready to lock the bond and submit."
        }
    }
}

struct AmberNetwork: Hashable, Sendable {
    let name: String
    let rpcURL: URL

    static let kanalenTestnet = AmberNetwork(
        name: "Kanalen testnet",
        rpcURL: URL(string: "https://rpc.kanalen.activechain.dev")!
    )
}

enum AmberConnectionState: Equatable, Sendable {
    case checking
    case verified(finalizedHeight: UInt64)
    case stale(finalizedHeight: UInt64)
    case degraded(finalizedHeight: UInt64)
    case unavailable
    case incompatible

    var label: String {
        switch self {
        case .checking: "Checking network"
        case let .verified(height): "Finalized #\(height)"
        case let .stale(height): "Stale at #\(height)"
        case let .degraded(height): "Degraded at #\(height)"
        case .unavailable: "Network unavailable"
        case .incompatible: "Protocol incompatible"
        }
    }

    var isAvailable: Bool {
        switch self {
        case .verified, .stale, .degraded: true
        case .checking, .unavailable, .incompatible: false
        }
    }
}

struct AmberNetworkRefreshPresentation: Equatable, Sendable {
    private(set) var isRefreshing = false
    private(set) var completedChecks = 0

    mutating func begin() -> Bool {
        guard !isRefreshing else {
            return false
        }
        isRefreshing = true
        return true
    }

    mutating func complete() {
        guard isRefreshing else {
            return
        }
        isRefreshing = false
        completedChecks += 1
    }

    var completionLabel: String? {
        completedChecks == 0 ? nil : "Checked now"
    }
}
