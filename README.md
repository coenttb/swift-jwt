# swift-jwt

A Swift package for creating, signing, and verifying JSON Web Tokens (JWTs) using Apple's Crypto framework. This package provides a convenient Swift wrapper around RFC 7519 JWT implementation with built-in cryptographic support.

## Features

- **Multiple Signing Algorithms**: HMAC-SHA256/384/512 and ECDSA-SHA256 support
- **Built on Standards**: Uses `swift-rfc-7519` for RFC compliance and `swift-crypto` for cryptography
- **Convenience Methods**: Easy-to-use static methods for common JWT operations
- **Flexible Configuration**: Full control over JWT headers, claims, and timing
- **Type Safety**: Leverages Swift's type system for secure JWT handling
- **Comprehensive Validation**: Signature verification with timing validation

## Requirements

- **Platforms**: macOS 13.0+, iOS 16.0+
- **Swift**: 5.9+ (Swift 6.0 supported)

## Installation

Add this package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/coenttb/swift-jwt.git", from: "0.1.0")
]
```

## Quick Start

### Creating JWTs

#### HMAC-SHA256 (Recommended for shared secrets)

```swift
import JWT

// Create a JWT with HMAC-SHA256
let jwt = try JWT.hmacSHA256(
    issuer: "example.com",
    subject: "user123",
    audience: "api.example.com",
    expiresIn: 3600, // 1 hour
    claims: ["role": "admin", "permissions": ["read", "write"]],
    secretKey: "your-secret-key"
)

// Get the token string
let tokenString = try jwt.compactSerialization()
```

#### ECDSA-SHA256 (Recommended for public/private key pairs)

```swift
import JWT
import Crypto

// Generate or load your ECDSA private key
let privateKey = P256.Signing.PrivateKey()

let jwt = try JWT.ecdsaSHA256(
    issuer: "secure-service",
    subject: "user456",
    audience: "mobile-app",
    expiresIn: 7200, // 2 hours
    claims: ["scope": "user:read"],
    privateKey: privateKey
)
```

### Verifying JWTs

#### HMAC Verification

```swift
import JWT

// Parse JWT from token string
let jwt = try JWT.parse(from: tokenString)

// Create verification key
let verificationKey = VerificationKey.symmetric(string: "your-secret-key")

// Verify signature only
let isValidSignature = try jwt.verify(with: verificationKey)

// Verify signature and validate timing (exp, nbf, iat)
let isFullyValid = try jwt.verifyAndValidate(with: verificationKey)
```

#### ECDSA Verification

```swift
import JWT

// Create verification key from public key
let verificationKey = VerificationKey.ecdsa(from: .ecdsa(privateKey))!

// Or from raw public key data
let publicKeyData = privateKey.publicKey.rawRepresentation
let verificationKey = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)

// Verify the JWT
let isValid = try jwt.verifyAndValidate(with: verificationKey)
```

## Advanced Usage

### Custom JWT Configuration

```swift
import JWT

let jwt = try JWT.signed(
    algorithm: .hmacSHA384,
    key: .symmetric(string: "custom-key"),
    issuer: "custom-issuer",
    subject: "user789",
    audiences: ["api1.example.com", "api2.example.com"], // Multiple audiences
    expiresAt: Date(timeIntervalSinceNow: 86400), // Custom expiration
    notBefore: Date(timeIntervalSinceNow: 300), // Valid in 5 minutes
    jti: UUID().uuidString, // JWT ID
    claims: [
        "role": "moderator",
        "permissions": ["read", "moderate"],
        "active": true
    ],
    headerParameters: [
        "kid": "key-identifier",
        "custom": "header-value"
    ]
)
```

### Working with Claims

```swift
// Access standard claims
print("Issuer: \(jwt.payload.iss ?? "Unknown")")
print("Subject: \(jwt.payload.sub ?? "Unknown")")
print("Expires: \(jwt.payload.exp?.description ?? "Never")")

// Access custom claims
let role = jwt.payload.additionalClaim("role", as: String.self)
let permissions = jwt.payload.additionalClaim("permissions", as: [String].self)
let isActive = jwt.payload.additionalClaim("active", as: Bool.self)
```

### Timing Validation

```swift
// Validate with custom timing parameters
let isValid = try jwt.verifyAndValidate(
    with: verificationKey,
    currentTime: Date(), // Custom current time
    clockSkew: 120 // Allow 2 minutes clock skew
)
```

### Key Management

```swift
// Symmetric keys
let stringKey = SigningKey.symmetric(string: "secret")
let dataKey = SigningKey.symmetric(data: keyData)

// ECDSA keys
let generatedKey = SigningKey.generateECDSA()
let existingKey = try SigningKey.ecdsa(rawRepresentation: privateKeyData)

// Verification keys
let symmetricVerify = VerificationKey.symmetric(string: "secret")
let ecdsaVerify = VerificationKey.ecdsa(from: signingKey)
let publicKeyVerify = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)
```

## Supported Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `HS256` | HMAC-SHA256 | Shared secret scenarios |
| `HS384` | HMAC-SHA384 | Enhanced security with shared secrets |
| `HS512` | HMAC-SHA512 | Maximum security with shared secrets |
| `ES256` | ECDSA-SHA256 | Public/private key scenarios |
| `none` | No signature | Testing only (not recommended for production) |

## Error Handling

The package throws RFC 7519 compliant errors:

```swift
do {
    let jwt = try JWT.hmacSHA256(/*...*/)
    let isValid = try jwt.verifyAndValidate(with: key)
} catch RFC_7519.Error.invalidSignature(let message) {
    print("Invalid signature: \(message)")
} catch RFC_7519.Error.tokenExpired {
    print("Token has expired")
} catch RFC_7519.Error.tokenNotYetValid {
    print("Token not yet valid")
} catch {
    print("Other error: \(error)")
}
```

## Dependencies

This package is built on top of:

- [swift-rfc-7519](https://github.com/swift-web-standards/swift-rfc-7519) - RFC 7519 compliant JWT implementation
- [swift-crypto](https://github.com/apple/swift-crypto) - Apple's cryptographic framework

## Security Considerations

- **Key Management**: Store secret keys securely and rotate them regularly
- **Algorithm Choice**: Use ECDSA for distributed systems, HMAC for simple scenarios
- **Token Expiration**: Always set appropriate expiration times
- **Timing Validation**: Enable timing validation in production
- **HTTPS Only**: Always transmit JWTs over HTTPS
- **Never Log Tokens**: Avoid logging JWTs in production systems

## Testing

Run the test suite:

```bash
swift test
```

The package includes comprehensive tests covering:
- JWT creation with all supported algorithms
- Signature verification
- Timing validation
- Edge cases and error conditions
- Key management operations

## Related projects

### The coenttb stack

* [swift-css](https://www.github.com/coenttb/swift-css): A Swift DSL for type-safe CSS.
* [swift-html](https://www.github.com/coenttb/swift-html): A Swift DSL for type-safe HTML & CSS, integrating [swift-css](https://www.github.com/coenttb/swift-css) and [pointfree-html](https://www.github.com/coenttb/pointfree-html).
* [swift-web](https://www.github.com/coenttb/swift-web): Foundational tools for web development in Swift.
* [coenttb-html](https://www.github.com/coenttb/coenttb-html): Builds on [swift-html](https://www.github.com/coenttb/swift-html), and adds functionality for HTML, Markdown, Email, and printing HTML to PDF.
* [coenttb-web](https://www.github.com/coenttb/coenttb-web): Builds on [swift-web](https://www.github.com/coenttb/swift-web), and adds functionality for web development.
* [coenttb-server](https://www.github.com/coenttb/coenttb-server): Build fast, modern, and safe servers that are a joy to write. `coenttb-server` builds on [coenttb-web](https://www.github.com/coenttb/coenttb-web), and adds functionality for server development.
* [coenttb-vapor](https://www.github.com/coenttb/coenttb-server-vapor): `coenttb-server-vapor` builds on [coenttb-server](https://www.github.com/coenttb/coenttb-server), and adds functionality and integrations with Vapor and Fluent.
* [coenttb-com-server](https://www.github.com/coenttb/coenttb-com-server): The backend server for coenttb.com, written entirely in Swift and powered by [coenttb-server-vapor](https://www.github.com/coenttb-server-vapor).

### PointFree foundations
* [coenttb/pointfree-html](https://www.github.com/coenttb/pointfree-html): A Swift DSL for type-safe HTML, forked from [pointfreeco/swift-html](https://www.github.com/pointfreeco/swift-html) and updated to the version on [pointfreeco/pointfreeco](https://github.com/pointfreeco/pointfreeco).
* [coenttb/pointfree-web](https://www.github.com/coenttb/pointfree-html): Foundational tools for web development in Swift, forked from  [pointfreeco/swift-web](https://www.github.com/pointfreeco/swift-web).
* [coenttb/pointfree-server](https://www.github.com/coenttb/pointfree-html): Foundational tools for server development in Swift, forked from  [pointfreeco/swift-web](https://www.github.com/pointfreeco/swift-web).

## Feedback is Much Appreciated!
  
If you're working on your own Swift project, feel free to learn, fork, and contribute.

Got thoughts? Found something you love? Something you hate? Let me know! Your feedback helps make this project better for everyone. Open an issue or start a discussion—I'm all ears.

> [Subscribe to my newsletter](http://coenttb.com/en/newsletter/subscribe)
>
> [Follow me on X](http://x.com/coenttb)
> 
> [Link on Linkedin](https://www.linkedin.com/in/tenthijeboonkkamp)

## License

This project is licensed under the **Apache 2.0 License**. See the [LICENSE](LICENSE).
