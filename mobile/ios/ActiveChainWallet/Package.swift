// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ActiveChainWallet",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "ActiveChainWallet", targets: ["ActiveChainWallet"])],
    dependencies: [.package(path: "../../../vendor/AnyIdentity")],
    targets: [
        .target(name: "ActiveChainWallet", dependencies: [.product(name: "AnyIdentity", package: "AnyIdentity")]),
        .testTarget(name: "ActiveChainWalletTests", dependencies: ["ActiveChainWallet", .product(name: "AnyIdentity", package: "AnyIdentity")])
    ]
)
