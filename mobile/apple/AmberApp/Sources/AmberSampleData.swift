import Foundation

enum AmberSampleData {
    static let boards: [AmberBoard] = {
        let now = Date(timeIntervalSince1970: 1_785_000_000)
        return [
            try! board(
                slug: "ac",
                title: "ActiveChain",
                summary: "Protocol engineering, testnet operations, and strange distributed systems.",
                activeUsers: 84,
                subjects: [
                    ("Kanalen testnet field notes", "Post validator observations, RPC quirks, and useful traces here."),
                    ("What should private apps feel like?", "Privacy should be legible without turning every action into a warning dialog."),
                ],
                now: now
            ),
            try! board(
                slug: "art",
                title: "Art & Images",
                summary: "Original work, process threads, scans, and generative experiments.",
                activeUsers: 31,
                subjects: [
                    ("Amber studies", "Warm palettes, hard shadows, imperfect print textures."),
                    ("Daily sketch thread", "One image, a few words, no portfolio links."),
                ],
                now: now.addingTimeInterval(-1_800)
            ),
            try! board(
                slug: "meta",
                title: "Amber Meta",
                summary: "Rules, moderation proposals, client feedback, and board governance.",
                activeUsers: 19,
                subjects: [
                    ("Welcome to the native preview", "This local preview uses bounded deterministic sample state."),
                ],
                now: now.addingTimeInterval(-3_600)
            ),
        ]
    }()

    private static func board(
        slug: String,
        title: String,
        summary: String,
        activeUsers: Int,
        subjects: [(String, String)],
        now: Date
    ) throws -> AmberBoard {
        let boardID = try AmberBoardID(slug)
        let threads = try subjects.enumerated().map { index, item in
            let number = UInt64(1_000 + subjects.count - index)
            let postID = AmberPostID(board: boardID, threadNumber: number, postNumber: 1)
            let post = try AmberPost(
                id: postID,
                body: item.1,
                createdAt: now.addingTimeInterval(TimeInterval(-index * 420))
            )
            return try AmberThread(
                board: boardID,
                number: number,
                generation: 1,
                subject: item.0,
                posts: [post]
            )
        }
        return try AmberBoard(
            id: boardID,
            title: title,
            summary: summary,
            activeUsers: activeUsers,
            threads: threads
        )
    }
}
