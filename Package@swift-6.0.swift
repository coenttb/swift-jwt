// swift-tools-version:6.0

import Foundation
import PackageDescription

extension String {
    static let jwt: Self = "JWT"
}

extension Target.Dependency {
    static var jwt: Self { .target(name: .jwt) }
}

extension Target.Dependency {
    static var crypto: Self { .product(name: "Crypto", package: "swift-crypto") }
    static var rfc7519: Self { .product(name: "RFC_7519", package: "swift-rfc-7519") }
}

let package = Package(
    name: "swift-jwt",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: .jwt, targets: [.jwt]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "3.0.0"),
        .package(url: "https://github.com/swift-web-standards/swift-rfc-7519.git", from: "0.0.1")
    ],
    targets: [
        .target(
            name: .jwt,
            dependencies: [
                .rfc7519,
                .crypto
            ]
        ),
        .testTarget(
            name: .jwt.tests,
            dependencies: [
                .jwt
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }
