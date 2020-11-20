// swift-tools-version:5.3

import PackageDescription

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/Luzanov/ChainedError", from: "0.0.1")
]

var targetDependencies: [Target.Dependency] = [
    .byName(name: "ChainedError"),
]

#if os(Linux)
packageDependencies.append(.package(url: "https://github.com/Luzanov/OpenSSL.git", from: "1.0.0"))
targetDependencies.append(.byName(name: "OpenSSL"))
#endif

let package = Package(
    name: "AES",
    products: [
        .library(name: "AES", targets: ["AES"])
    ],
    dependencies: packageDependencies,
    targets: [
        .target( name: "AES", dependencies: targetDependencies),
        .testTarget(name: "AESTests", dependencies: ["AES"])
    ]
)
