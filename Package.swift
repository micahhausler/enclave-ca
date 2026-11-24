// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "enclave-ca",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "enclave-ca", targets: ["enclave-ca"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.1"),
    ],
    targets: [
        .target(
            name: "EnclaveCA",
            dependencies: [.product(name: "X509", package: "swift-certificates")]
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
