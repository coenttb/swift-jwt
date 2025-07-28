//
//  RFC 7519+Crypto.swift
//  RFC_7519JWTCrypto
//
//  Created by Generated on 2025-07-28.
//

import Foundation
import RFC_7519
import Crypto

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
public enum SigningAlgorithm {
    case hmacSHA256
    case hmacSHA384
    case hmacSHA512
    case ecdsaSHA256
    case none
    
    /// The algorithm name as it appears in the JWT header
    public var algorithmName: String {
        switch self {
        case .hmacSHA256: return "HS256"
        case .hmacSHA384: return "HS384"
        case .hmacSHA512: return "HS512"
        case .ecdsaSHA256: return "ES256"
        case .none: return "none"
        }
    }
    
    /// Signs data with the specified key using swift-crypto
    /// - Parameters:
    ///   - data: Data to sign
    ///   - key: Signing key
    /// - Returns: Signature data
    /// - Throws: `Error` if signing fails
    func sign(data: Data, with key: SigningKey) throws -> Data {
        switch self {
        case .hmacSHA256:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
            
        case .hmacSHA384:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
            
        case .hmacSHA512:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
            
        case .ecdsaSHA256:
            guard case .ecdsa(let privateKey) = key else {
                throw RFC_7519.Error.invalidSignature("ECDSA requires ECDSA private key")
            }
            return try privateKey.signature(for: SHA256.hash(data: data)).rawRepresentation
            
        case .none:
            return Data()
        }
    }
    
    /// Verifies a signature using swift-crypto
    /// - Parameters:
    ///   - signature: Signature to verify
    ///   - data: Original data that was signed
    ///   - key: Verification key
    /// - Returns: True if signature is valid
    /// - Throws: `Error` if verification fails
    public func verify(signature: Data, for data: Data, with key: VerificationKey) throws -> Bool {
        switch self {
        case .hmacSHA256:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
            
        case .hmacSHA384:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
            
        case .hmacSHA512:
            guard case .symmetric(let symmetricKey) = key else {
                throw RFC_7519.Error.invalidSignature("HMAC requires symmetric key")
            }
            let expectedSignature = Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
            return signature == expectedSignature
            
        case .ecdsaSHA256:
            guard case .ecdsa(let publicKey) = key else {
                throw RFC_7519.Error.invalidSignature("ECDSA requires ECDSA public key")
            }
            let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return publicKey.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
            
        case .none:
            return signature.isEmpty
        }
    }
}

// MARK: - Signing Keys with swift-crypto

/// Represents a key for signing JWTs using swift-crypto
public enum SigningKey {
    case symmetric(SymmetricKey)
    case ecdsa(P256.Signing.PrivateKey)
    
    /// Creates a symmetric key from data
    /// - Parameter data: Key data
    /// - Returns: Signing key
    public static func symmetric(data: Data) -> SigningKey {
        return .symmetric(SymmetricKey(data: data))
    }
    
    /// Creates a symmetric key from string
    /// - Parameter string: Key string (UTF-8 encoded)
    /// - Returns: Signing key
    public static func symmetric(string: String) -> SigningKey {
        return .symmetric(SymmetricKey(data: Data(string.utf8)))
    }
    
    /// Generates a new ECDSA P-256 private key
    /// - Returns: Signing key
    public static func generateECDSA() -> SigningKey {
        return .ecdsa(P256.Signing.PrivateKey())
    }
    
    /// Creates an ECDSA private key from raw representation
    /// - Parameter rawRepresentation: Raw key data
    /// - Returns: Signing key
    /// - Throws: Error if key is invalid
    public static func ecdsa(rawRepresentation: Data) throws -> SigningKey {
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        return .ecdsa(privateKey)
    }
}

/// Represents a key for verifying JWTs using swift-crypto
public enum VerificationKey {
    case symmetric(SymmetricKey)
    case ecdsa(P256.Signing.PublicKey)
    
    /// Creates a symmetric key from data
    /// - Parameter data: Key data
    /// - Returns: Verification key
    public static func symmetric(data: Data) -> VerificationKey {
        return .symmetric(SymmetricKey(data: data))
    }
    
    /// Creates a symmetric key from string
    /// - Parameter string: Key string (UTF-8 encoded)
    /// - Returns: Verification key
    public static func symmetric(string: String) -> VerificationKey {
        return .symmetric(SymmetricKey(data: Data(string.utf8)))
    }
    
    /// Creates an ECDSA public key from a signing key
    /// - Parameter signingKey: ECDSA signing key
    /// - Returns: Verification key
    public static func ecdsa(from signingKey: SigningKey) -> VerificationKey? {
        guard case .ecdsa(let privateKey) = signingKey else { return nil }
        return .ecdsa(privateKey.publicKey)
    }
    
    /// Creates an ECDSA public key from raw representation
    /// - Parameter rawRepresentation: Raw key data
    /// - Returns: Verification key
    /// - Throws: Error if key is invalid
    public static func ecdsa(rawRepresentation: Data) throws -> VerificationKey {
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: rawRepresentation)
        return .ecdsa(publicKey)
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
        return try algorithm.verify(signature: signature, for: signingInput, with: key)
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
        
        // Create header
        let header = Header(
            alg: algorithm.algorithmName,
            typ: "JWT",
            cty: nil,
            kid: nil,
            additionalParameters: headerParameters.isEmpty ? nil : headerParameters
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
        let signature = try algorithm.sign(data: signingInput, with: key)
        
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
