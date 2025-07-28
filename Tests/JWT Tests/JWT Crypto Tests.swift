//
//  JWT Crypto Tests.swift
//  RFC_7519JWTCrypto Tests
//
//  Created by Generated on 2025-07-28.
//

import Testing
import Foundation
import Crypto
@testable import JWT

@Suite("JWT Crypto Tests")
struct JWT_Crypto_Tests {
    
    // MARK: - JWT Creation with swift-crypto Tests
    
    @Test("JWT creation with HMAC-SHA256")
    func testJWTHMACSHA256() throws {
        let jwt = try JWT.hmacSHA256(
            issuer: "example.com",
            subject: "user123",
            audience: "api.example.com",
            expiresIn: 3600,
            claims: ["role": "admin", "permissions": ["read", "write"]],
            secretKey: "my-secret-key"
        )
        
        #expect(jwt.header.alg == "HS256")
        #expect(jwt.header.typ == "JWT")
        #expect(jwt.payload.iss == "example.com")
        #expect(jwt.payload.sub == "user123")
        #expect(jwt.payload.aud?.values == ["api.example.com"])
        #expect(jwt.payload.exp != nil)
        #expect(jwt.payload.iat != nil)
        #expect(jwt.payload.additionalClaim("role", as: String.self) == "admin")
        
        // Verify the token can be parsed back
        let tokenString = try jwt.compactSerialization()
        let parsedJWT = try JWT.parse(from: tokenString)
        
        #expect(parsedJWT.payload.iss == jwt.payload.iss)
        #expect(parsedJWT.payload.sub == jwt.payload.sub)
    }
    
    
    @Test("JWT creation with ECDSA-SHA256")
    func testJWTECDSASHA256() throws {
        let privateKey = P256.Signing.PrivateKey()
        let verificationKey = VerificationKey.ecdsa(from: .ecdsa(privateKey))!
        
        let jwt = try JWT.ecdsaSHA256(
            issuer: "ecdsa-issuer",
            subject: "ecdsa-user",
            audience: "ecdsa-api",
            expiresIn: 7200,
            claims: ["custom": "value"],
            privateKey: privateKey
        )
        
        #expect(jwt.header.alg == "ES256")
        #expect(jwt.payload.iss == "ecdsa-issuer")
        
        // Verify signature
        let isValid = try jwt.verify(with: verificationKey)
        #expect(isValid)
    }
    
    @Test("JWT creation with multiple audiences using swift-crypto")
    func testJWTMultipleAudiences() throws {
        let jwt = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "test-key"),
            issuer: "multi-aud-issuer",
            subject: "user",
            audiences: ["api1.example.com", "api2.example.com", "api3.example.com"],
            expiresIn: 3600
        )
        
        #expect(jwt.payload.aud?.values == ["api1.example.com", "api2.example.com", "api3.example.com"])
    }
    
    @Test("JWT creation with timing controls using swift-crypto")
    func testJWTTimingControls() throws {
        let customIat = Date(timeIntervalSinceNow: -60) // 1 minute ago
        let customExp = Date(timeIntervalSinceNow: 7200) // 2 hours from now
        let customNbf = Date(timeIntervalSinceNow: 300) // 5 minutes from now
        
        let jwt = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "timing-key"),
            issuer: "timing-issuer",
            subject: "timing-user",
            expiresAt: customExp,
            notBefore: customNbf,
            issuedAt: customIat
        )
        
        #expect(abs(jwt.payload.iat!.timeIntervalSince1970 - customIat.timeIntervalSince1970) < 1.0)
        #expect(abs(jwt.payload.exp!.timeIntervalSince1970 - customExp.timeIntervalSince1970) < 1.0)
        #expect(abs(jwt.payload.nbf!.timeIntervalSince1970 - customNbf.timeIntervalSince1970) < 1.0)
    }
    
    @Test("JWT creation with custom header parameters using swift-crypto")
    func testJWTCustomHeaders() throws {
        let jwt = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "header-key"),
            issuer: "header-issuer",
            subject: "user",
            expiresIn: 3600,
            headerParameters: ["custom": "header-value", "version": 2]
        )
        
        #expect(jwt.header.additionalParameter("custom", as: String.self) == "header-value")
        #expect(jwt.header.additionalParameter("version", as: Int.self) == 2)
    }
    
    // MARK: - Convenience Method Tests
    
    @Test("JWT HMAC-SHA256 convenience method")
    func testJWTHMACConvenience() throws {
        let jwt = try JWT.hmacSHA256(
            issuer: "convenience-issuer",
            subject: "convenience-user",
            audience: "convenience-api",
            expiresIn: 1800,
            claims: ["role": "user", "active": true],
            secretKey: "convenience-key"
        )
        
        #expect(jwt.header.alg == "HS256")
        #expect(jwt.payload.iss == "convenience-issuer")
        #expect(jwt.payload.sub == "convenience-user")
        #expect(jwt.payload.aud?.values == ["convenience-api"])
        #expect(jwt.payload.additionalClaim("role", as: String.self) == "user")
        #expect(jwt.payload.additionalClaim("active", as: Bool.self) == true)
        
        // Verify the token
        let verificationKey = VerificationKey.symmetric(string: "convenience-key")
        let isValid = try jwt.verify(with: verificationKey)
        #expect(isValid)
    }
    
    @Test("JWT HMAC-SHA384 convenience method")
    func testJWTHMAC384Convenience() throws {
        let jwt = try JWT.hmacSHA384(
            issuer: "no-aud-issuer",
            subject: "no-aud-user",
            secretKey: "no-aud-key"
        )
        
        #expect(jwt.header.alg == "HS384")
        #expect(jwt.payload.aud == nil)
        #expect(jwt.payload.iss == "no-aud-issuer")
        #expect(jwt.payload.sub == "no-aud-user")
    }
    
    // MARK: - Signature Verification Tests
    
    @Test("JWT signature verification with HMAC")
    func testJWTVerificationHMAC() throws {
        let verificationKey = VerificationKey.symmetric(string: "verification-key")
        let wrongKey = VerificationKey.symmetric(string: "wrong-key")
        
        let jwt = try JWT.hmacSHA256(
            issuer: "verify-issuer",
            subject: "verify-user",
            expiresIn: 3600,
            secretKey: "verification-key"
        )
        
        // Correct key should verify
        let isValidCorrect = try jwt.verify(with: verificationKey)
        #expect(isValidCorrect)
        
        // Wrong key should fail
        let isValidWrong = try jwt.verify(with: wrongKey)
        #expect(!isValidWrong)
    }
    
    @Test("JWT verification with timing validation")
    func testJWTVerificationWithTiming() throws {
        let verificationKey = VerificationKey.symmetric(string: "timing-verify-key")
        
        // Create expired token
        let expiredJWT = try JWT.hmacSHA256(
            issuer: "expired-issuer",
            subject: "expired-user",
            expiresIn: -3600, // Expired 1 hour ago
            secretKey: "timing-verify-key"
        )
        
        // Signature should be valid but timing should fail
        let isSignatureValid = try expiredJWT.verify(with: verificationKey)
        #expect(isSignatureValid)
        
        #expect(throws: RFC_7519.Error.self) {
            try expiredJWT.verifyAndValidate(with: verificationKey)
        }
        
        // Create valid token
        let validJWT = try JWT.hmacSHA256(
            issuer: "valid-issuer",
            subject: "valid-user",
            expiresIn: 3600,
            secretKey: "timing-verify-key"
        )
        
        // Both signature and timing should be valid
        let isValid = try validJWT.verifyAndValidate(with: verificationKey)
        #expect(isValid)
    }
    
    @Test("JWT verification with not-yet-valid token")
    func testJWTVerificationNotYetValid() throws {
        let verificationKey = VerificationKey.symmetric(string: "nbf-key")
        
        let jwt = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "nbf-key"),
            issuer: "nbf-issuer",
            subject: "nbf-user",
            expiresIn: 7200, // Expires in 2 hours
            notBefore: Date(timeIntervalSinceNow: 3600) // Valid in 1 hour
        )
        
        // Signature should be valid but timing should fail
        let isSignatureValid = try jwt.verify(with: verificationKey)
        #expect(isSignatureValid)
        
        #expect(throws: RFC_7519.Error.self) {
            try jwt.verifyAndValidate(with: verificationKey)
        }
    }
    
    // MARK: - Algorithm Tests
    
    @Test("Signing algorithm names")
    func testSigningAlgorithmNames() {
        #expect(SigningAlgorithm.hmacSHA256.algorithmName == "HS256")
        #expect(SigningAlgorithm.hmacSHA384.algorithmName == "HS384")
        #expect(SigningAlgorithm.hmacSHA512.algorithmName == "HS512")
        #expect(SigningAlgorithm.ecdsaSHA256.algorithmName == "ES256")
        #expect(SigningAlgorithm.none.algorithmName == "none")
    }
    
    @Test("Algorithm from string")
    func testAlgorithmFromString() {
        #expect(SigningAlgorithm.from(algorithmName: "HS256") == .hmacSHA256)
        #expect(SigningAlgorithm.from(algorithmName: "HS384") == .hmacSHA384)
        #expect(SigningAlgorithm.from(algorithmName: "HS512") == .hmacSHA512)
        #expect(SigningAlgorithm.from(algorithmName: "ES256") == .ecdsaSHA256)
        #expect(SigningAlgorithm.from(algorithmName: "none") == SigningAlgorithm.none)
        #expect(SigningAlgorithm.from(algorithmName: "UNKNOWN") == nil)
    }
    
    // MARK: - Key Creation Tests
    
    @Test("Symmetric key creation")
    func testSymmetricKeyCreation() throws {
        let stringKey = SigningKey.symmetric(string: "test-key")
        let dataKey = SigningKey.symmetric(data: Data("test-key".utf8))
        
        // Both should work for signing (can't directly compare the keys)
        let jwt1 = try JWT.signed(
            algorithm: .hmacSHA256,
            key: stringKey,
            issuer: "key-test",
            subject: "user",
            expiresIn: 3600
        )
        
        let jwt2 = try JWT.signed(
            algorithm: .hmacSHA256,
            key: dataKey,
            issuer: "key-test",
            subject: "user",
            expiresIn: 3600
        )
        
        // Verify with equivalent verification keys
        let verifyKey1 = VerificationKey.symmetric(string: "test-key")
        let verifyKey2 = VerificationKey.symmetric(data: Data("test-key".utf8))
        
        #expect((try? jwt1.verify(with: verifyKey1)) == true)
        #expect((try? jwt1.verify(with: verifyKey2)) == true)
        #expect((try? jwt2.verify(with: verifyKey1)) == true)
        #expect((try? jwt2.verify(with: verifyKey2)) == true)
    }
    
    @Test("ECDSA key generation")
    func testECDSAKeyGeneration() throws {
        let signingKey = SigningKey.generateECDSA()
        let verificationKey = VerificationKey.ecdsa(from: signingKey)!
        
        let jwt = try JWT.signed(
            algorithm: .ecdsaSHA256,
            key: signingKey,
            issuer: "ecdsa-gen-test",
            subject: "user",
            expiresIn: 3600
        )
        
        let isValid = try jwt.verify(with: verificationKey)
        #expect(isValid)
    }
    
    // MARK: - Edge Cases
    
    @Test("JWT with no algorithm (none)")
    func testJWTWithNoAlgorithm() throws {
        let jwt = try JWT.signed(
            algorithm: .none,
            key: .symmetric(string: "ignored"),
            issuer: "none-issuer",
            subject: "none-user",
            expiresIn: 3600
        )
        
        #expect(jwt.header.alg == "none")
        #expect(jwt.signature.isEmpty)
        
        // Verification should work with any key for 'none' algorithm
        let verificationKey = VerificationKey.symmetric(string: "any-key")
        let isValid = try jwt.verify(with: verificationKey)
        #expect(isValid)
    }
    
    @Test("JWT static method with full configuration")
    func testJWTStaticMethodFullConfiguration() throws {
        let jwt = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "chain-key"),
            issuer: "chain-issuer",
            subject: "chain-user",
            audience: "chain-api",
            expiresIn: 3600,
            notBefore: Date(timeIntervalSinceNow: -60),
            jti: UUID().uuidString,
            claims: ["role": "admin", "active": true, "score": 95],
            headerParameters: ["custom": "value", "kid": "chain-key-1", "cty": "application/json"]
        )
        
        #expect(jwt.payload.iss == "chain-issuer")
        #expect(jwt.payload.sub == "chain-user")
        #expect(jwt.payload.aud?.values == ["chain-api"])
        #expect(jwt.payload.jti != nil)
        #expect(jwt.header.additionalParameter("cty", as: String.self) == "application/json")
        #expect(jwt.header.additionalParameter("kid", as: String.self) == "chain-key-1")
        #expect(jwt.payload.additionalClaim("role", as: String.self) == "admin")
        #expect(jwt.payload.additionalClaim("active", as: Bool.self) == true)
        #expect(jwt.payload.additionalClaim("score", as: Int.self) == 95)
    }
}
