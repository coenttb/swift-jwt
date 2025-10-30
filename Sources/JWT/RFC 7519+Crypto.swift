//
//  RFC 7519+Crypto.swift
//  RFC_7519JWTCrypto
//
//  Created by Generated on 2025-07-28.
//

import Foundation
import RFC_7519
@preconcurrency import Crypto

// MARK: - JWT Creation with swift-crypto

extension RFC_7519.JWT {
    /// Creates a JWT with common claims using HMAC-SHA256
    /// - Parameters:
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - claims: Additional custom claims
    ///   - secretKey: HMAC secret key
    /// - Returns: Signed JWT
    /// - Throws: `Error` if creation fails
    public static func hmacSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws -> RFC_7519.JWT {
        return try signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
    
    /// Creates a JWT with common claims using HMAC-SHA384
    /// - Parameters:
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - claims: Additional custom claims
    ///   - secretKey: HMAC secret key
    /// - Returns: Signed JWT
    /// - Throws: `Error` if creation fails
    public static func hmacSHA384(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws -> RFC_7519.JWT {
        return try signed(
            algorithm: .hmacSHA384,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
    
    /// Creates a JWT with common claims using HMAC-SHA512
    /// - Parameters:
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - claims: Additional custom claims
    ///   - secretKey: HMAC secret key
    /// - Returns: Signed JWT
    /// - Throws: `Error` if creation fails
    public static func hmacSHA512(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws -> RFC_7519.JWT {
        return try signed(
            algorithm: .hmacSHA512,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
    
    /// Creates a JWT with common claims using ECDSA-SHA256
    /// - Parameters:
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - claims: Additional custom claims
    ///   - privateKey: ECDSA private key
    /// - Returns: Signed JWT
    /// - Throws: `Error` if creation fails
    public static func ecdsaSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        privateKey: P256.Signing.PrivateKey
    ) throws -> RFC_7519.JWT {
        return try signed(
            algorithm: .ecdsaSHA256,
            key: .ecdsa(privateKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
}

// MARK: - Signing Algorithms with swift-crypto

/// Represents a JWT signing algorithm with swift-crypto implementation
public struct SigningAlgorithm: Sendable {
    /// The algorithm name as it appears in the JWT header
    public let algorithmName: String
    
    /// Signs data with the specified key
    public let sign: @Sendable (Data, SigningKey) throws -> Data
    
    /// Verifies a signature
    public let verify: @Sendable (Data, Data, VerificationKey) throws -> Bool
    
    /// Creates a custom signing algorithm
    public init(
        algorithmName: String,
        sign: @escaping @Sendable (Data, SigningKey) throws -> Data,
        verify: @escaping @Sendable (Data, Data, VerificationKey) throws -> Bool
    ) {
        self.algorithmName = algorithmName
        self.sign = sign
        self.verify = verify
    }
    
    /// Standard HMAC-SHA256 algorithm
    public static let hmacSHA256 = SigningAlgorithm(
        algorithmName: "HS256",
        sign: { data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
        }
    )
    
    /// Standard HMAC-SHA384 algorithm
    public static let hmacSHA384 = SigningAlgorithm(
        algorithmName: "HS384",
        sign: { data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
        }
    )
    
    /// Standard HMAC-SHA512 algorithm
    public static let hmacSHA512 = SigningAlgorithm(
        algorithmName: "HS512",
        sign: { data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key in
            guard let symmetricKey = key._symmetricKey else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
        }
    )
    
    /// Standard ECDSA-SHA256 algorithm
    public static let ecdsaSHA256 = SigningAlgorithm(
        algorithmName: "ES256",
        sign: { data, key in
            guard let privateKey = key._ecdsaPrivateKey else {
                throw RFC_7519.Error.invalidSignature("ECDSA requires ECDSA private key")
            }
            return try privateKey.signature(for: SHA256.hash(data: data)).rawRepresentation
        },
        verify: { signature, data, key in
            guard let publicKey = key._ecdsaPublicKey else {
                throw RFC_7519.Error.invalidSignature("ECDSA requires ECDSA public key")
            }
            let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return publicKey.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
        }
    )
    
    /// No signature algorithm - WARNING: This provides no security!
    /// Only use when the JWT is already verified through other means (e.g., secure transport)
    /// RFC 7518: "none" should only be used in contexts where the JWT is integrity protected by other means
    public static let none = SigningAlgorithm(
        algorithmName: "none",
        sign: { _, _ in Data() },
        verify: { signature, _, _ in signature.isEmpty }
    )
    
    /// Enum for type-safe standard algorithm selection
    public enum Standard {
        case hmacSHA256
        case hmacSHA384
        case hmacSHA512
        case ecdsaSHA256
        case none
        
        /// Gets the corresponding SigningAlgorithm
        public var algorithm: SigningAlgorithm {
            switch self {
            case .hmacSHA256: return .hmacSHA256
            case .hmacSHA384: return .hmacSHA384
            case .hmacSHA512: return .hmacSHA512
            case .ecdsaSHA256: return .ecdsaSHA256
            case .none: return .none
            }
        }
    }
}

// MARK: - Signing Keys with swift-crypto

/// Represents a key for signing JWTs using swift-crypto
public struct SigningKey: Sendable {
    /// Internal storage for the key
    private let storage: Storage
    
    /// Internal key storage
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PrivateKey)
    }
    
    /// Creates a signing key with internal storage
    private init(storage: Storage) {
        self.storage = storage
    }
    
    /// Creates a symmetric key from data
    /// - Parameter data: Key data
    /// - Returns: Signing key
    public static func symmetric(data: Data) -> SigningKey {
        return SigningKey(storage: .symmetric(SymmetricKey(data: data)))
    }
    
    /// Creates a symmetric key from string
    /// - Parameter string: Key string (UTF-8 encoded)
    /// - Returns: Signing key
    /// - Important: For HMAC algorithms, RFC 7518 recommends key length >= hash output length:
    ///   - HS256: >= 32 bytes (256 bits)
    ///   - HS384: >= 48 bytes (384 bits)
    ///   - HS512: >= 64 bytes (512 bits)
    public static func symmetric(string: String) -> SigningKey {
        return SigningKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }
    
    /// Creates an ECDSA signing key
    /// - Parameter privateKey: ECDSA private key
    /// - Returns: Signing key
    public static func ecdsa(_ privateKey: P256.Signing.PrivateKey) -> SigningKey {
        return SigningKey(storage: .ecdsa(privateKey))
    }
    
    /// Generates a new ECDSA P-256 private key
    /// - Returns: Signing key
    public static func generateECDSA() -> SigningKey {
        return SigningKey(storage: .ecdsa(P256.Signing.PrivateKey()))
    }
    
    /// Creates an ECDSA private key from raw representation
    /// - Parameter rawRepresentation: Raw key data
    /// - Returns: Signing key
    /// - Throws: Swift.Error if key is invalid
    public static func ecdsa(rawRepresentation: Data) throws -> SigningKey {
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        return SigningKey(storage: .ecdsa(privateKey))
    }
    
    /// Internal access to symmetric key
    internal var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }
    
    /// Internal access to ECDSA private key
    internal var _ecdsaPrivateKey: P256.Signing.PrivateKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}

/// Represents a key for verifying JWTs using swift-crypto
public struct VerificationKey: Sendable {
    /// Internal storage for the key
    private let storage: Storage
    
    /// Internal key storage
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PublicKey)
    }
    
    /// Creates a verification key with internal storage
    private init(storage: Storage) {
        self.storage = storage
    }
    
    /// Creates a symmetric key from data
    /// - Parameter data: Key data
    /// - Returns: Verification key
    public static func symmetric(data: Data) -> VerificationKey {
        return VerificationKey(storage: .symmetric(SymmetricKey(data: data)))
    }
    
    /// Creates a symmetric key from string
    /// - Parameter string: Key string (UTF-8 encoded)
    /// - Returns: Verification key
    public static func symmetric(string: String) -> VerificationKey {
        return VerificationKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }
    
    /// Creates an ECDSA verification key
    /// - Parameter publicKey: ECDSA public key
    /// - Returns: Verification key
    public static func ecdsa(_ publicKey: P256.Signing.PublicKey) -> VerificationKey {
        return VerificationKey(storage: .ecdsa(publicKey))
    }
    
    /// Creates an ECDSA public key from a signing key
    /// - Parameter signingKey: ECDSA signing key
    /// - Returns: Verification key
    public static func ecdsa(from signingKey: SigningKey) -> VerificationKey? {
        guard let privateKey = signingKey._ecdsaPrivateKey else { return nil }
        return VerificationKey(storage: .ecdsa(privateKey.publicKey))
    }
    
    /// Creates an ECDSA public key from raw representation
    /// - Parameter rawRepresentation: Raw key data
    /// - Returns: Verification key
    /// - Throws: Swift.Error if key is invalid
    public static func ecdsa(rawRepresentation: Data) throws -> VerificationKey {
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: rawRepresentation)
        return VerificationKey(storage: .ecdsa(publicKey))
    }
    
    /// Internal access to symmetric key
    internal var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }
    
    /// Internal access to ECDSA public key
    internal var _ecdsaPublicKey: P256.Signing.PublicKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}

// MARK: - JWT Verification with swift-crypto

extension RFC_7519.JWT {
    /// Verifies the JWT signature using swift-crypto
    /// - Parameter key: Verification key
    /// - Returns: True if signature is valid
    /// - Throws: `Error` if verification fails
    public func verify(with key: VerificationKey) throws -> Bool {
        guard let algorithm = SigningAlgorithm.from(algorithmName: header.alg) else {
            throw RFC_7519.Error.unsupportedAlgorithm("Unsupported algorithm: \(header.alg)")
        }
        
        let signingInput = try self.signingInput()
        return try algorithm.verify(signature, signingInput, key)
    }
    
    /// Verifies the JWT signature and validates timing claims using swift-crypto
    /// - Parameters:
    ///   - key: Verification key
    ///   - currentTime: Current time for validation (defaults to now)
    ///   - clockSkew: Allowed clock skew in seconds (defaults to 60)
    /// - Returns: True if signature and timing are valid
    /// - Throws: `Error` if verification or validation fails
    public func verifyAndValidate(
        with key: VerificationKey,
        currentTime: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> Bool {
        // First verify signature
        let isValidSignature = try verify(with: key)
        guard isValidSignature else { return false }
        
        // Then validate timing
        try payload.validateTiming(currentTime: currentTime, clockSkew: clockSkew)
        
        return true
    }
}

// MARK: - JWT Creation with Generic Signing (swift-crypto Implementation)

extension RFC_7519.JWT {
    /// Creates a JWT with custom configuration using swift-crypto
    /// - Parameters:
    ///   - algorithm: Signing algorithm
    ///   - key: Signing key
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - notBefore: Not before time (optional)
    ///   - issuedAt: Issued at time (defaults to now)
    ///   - jti: JWT ID (optional)
    ///   - claims: Additional custom claims
    ///   - headerParameters: Additional header parameters
    /// - Returns: Signed JWT
    /// - Throws: `Error` if creation fails
    public static func signed(
        algorithm: SigningAlgorithm,
        key: SigningKey,
        issuer: String? = nil,
        subject: String? = nil,
        audience: String? = nil,
        audiences: [String]? = nil,
        expiresIn: TimeInterval? = nil,
        expiresAt: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = Date(),
        jti: String? = nil,
        claims: [String: Any] = [:],
        headerParameters: [String: Any] = [:]
    ) throws -> RFC_7519.JWT {
        // Determine audience
        let aud: Payload.Audience?
        if let audiences = audiences {
            aud = Payload.Audience(audiences)
        } else if let audience = audience {
            aud = .single(audience)
        } else {
            aud = nil
        }
        
        // Determine expiration
        let exp: Date?
        if let expiresAt = expiresAt {
            exp = expiresAt
        } else if let expiresIn = expiresIn {
            exp = Date(timeIntervalSinceNow: expiresIn)
        } else {
            exp = nil
        }
        
        // Create header - extract standard header parameters
        var filteredHeaderParameters = headerParameters
        
        // Note: 'alg' is NOT extracted from headerParameters for security reasons
        // It must always come from the algorithm parameter
        
        let typ = filteredHeaderParameters.removeValue(forKey: "typ") as? String ?? "JWT"
        let cty = filteredHeaderParameters.removeValue(forKey: "cty") as? String
        let kid = filteredHeaderParameters.removeValue(forKey: "kid") as? String
        
        // Additional standard parameters remain in additionalParameters
        // (jku, jwk, x5u, x5c, x5t, x5t#S256, crit)
        
        let header = Header(
            alg: algorithm.algorithmName,
            typ: typ,
            cty: cty,
            kid: kid,
            additionalParameters: filteredHeaderParameters.isEmpty ? nil : filteredHeaderParameters
        )
        
        // Create payload
        let payload = Payload(
            iss: issuer,
            sub: subject,
            aud: aud,
            exp: exp,
            nbf: notBefore,
            iat: issuedAt,
            jti: jti,
            additionalClaims: claims.isEmpty ? nil : claims
        )
        
        // Create JWT with empty signature first
        let unsignedJWT = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        // Get signing input
        let signingInput = try unsignedJWT.signingInput()
        
        // Sign the data
        let signature = try algorithm.sign(signingInput, key)
        
        // Return signed JWT
        return RFC_7519.JWT(header: header, payload: payload, signature: signature)
    }
}

// MARK: - Algorithm Helper

extension SigningAlgorithm {
    /// Creates a signing algorithm from its string name
    /// - Parameter algorithmName: Algorithm name (e.g., "HS256")
    /// - Returns: Signing algorithm or nil if unsupported
    public static func from(algorithmName: String) -> SigningAlgorithm? {
        switch algorithmName {
        case "HS256": return .hmacSHA256
        case "HS384": return .hmacSHA384
        case "HS512": return .hmacSHA512
        case "ES256": return .ecdsaSHA256
        case "none": return SigningAlgorithm.none
        default: return nil
        }
    }
}
