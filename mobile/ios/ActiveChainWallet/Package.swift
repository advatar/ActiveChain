// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ActiveChainWallet", products: [.library(name: "ActiveChainWallet", targets: ["ActiveChainWallet"])], targets: [.target(name: "ActiveChainWallet"), .testTarget(name: "ActiveChainWalletTests", dependencies: ["ActiveChainWallet"])])
