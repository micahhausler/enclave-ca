// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "enclave-ca",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "enclave-ca", targets: ["enclave-ca"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.4"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.1.1"),
    ],
    targets: [
        .target(
            name: "EnclaveCA",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "enclave-ca",
            dependencies: ["EnclaveCA"]
        ),
        .testTarget(
            name: "EnclaveCATests",
            dependencies: ["EnclaveCA"],
            exclude: ["Fixtures"]
        ),
    ]
)
