// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AnyIdentity",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "AnyIdentity", targets: ["AnyIdentity"]),
        .executable(name: "AuthorityDemo", targets: ["AuthorityDemo"])
    ],
    targets: [
        .binaryTarget(name: "CAnyIdentity", path: "Artifacts/CAnyIdentity.xcframework"),
        .target(name: "AnyIdentity", dependencies: ["CAnyIdentity"],
                linkerSettings: [.linkedFramework("Security"), .linkedLibrary("resolv")]),
        .executableTarget(name: "AuthorityDemo", dependencies: ["AnyIdentity"], path: "Examples/AuthorityDemo"),
        .testTarget(name: "AnyIdentityTests", dependencies: ["AnyIdentity"])
    ]
)
