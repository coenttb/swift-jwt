//
//  File.swift
//  swift-web
//
//  Created by Coen ten Thije Boonkkamp on 28/07/2025.
//

import Foundation
import RFC_7519

public typealias JWT = RFC_7519.JWT

extension JWT {
  /// Convenience accessor for the full JWT string representation
  public var token: String {
    get throws {
      try self.compactSerialization()
    }
  }
}

extension JWT.Header {
  /// The algorithm used to sign the JWT (same as `alg`)
  public var algorithm: String {
    alg
  }

  /// The type of token (same as `typ`)
  public var type: String? {
    typ
  }

  /// The content type (same as `cty`)
  public var contentType: String? {
    cty
  }

  /// The key ID (same as `kid`)
  public var keyId: String? {
    kid
  }
}

extension JWT.Payload {
  /// The issuer of the JWT (same as `iss`)
  public var issuer: String? {
    iss
  }

  /// The subject of the JWT (same as `sub`)
  public var subject: String? {
    sub
  }

  /// The audience of the JWT (same as `aud`)
  public var audience: Audience? {
    aud
  }

  /// The expiration time (same as `exp`)
  public var expirationTime: Date? {
    exp
  }

  /// The not before time (same as `nbf`)
  public var notBeforeTime: Date? {
    nbf
  }

  /// The issued at time (same as `iat`)
  public var issuedAtTime: Date? {
    iat
  }

  /// The JWT ID (same as `jti`)
  public var id: String? {
    jti
  }

  // Convenience computed properties

  /// Check if the token is expired
  public var isExpired: Bool {
    guard let expirationTime = exp else { return false }
    return expirationTime < Date()
  }

  /// Check if the token is not yet valid
  public var isNotYetValid: Bool {
    guard let notBefore = nbf else { return false }
    return notBefore > Date()
  }

  /// Check if the token is currently valid (not expired and not before nbf)
  public var isCurrentlyValid: Bool {
    !isExpired && !isNotYetValid
  }

  /// Get the remaining time until expiration in seconds
  public var timeUntilExpiration: TimeInterval? {
    guard let expirationTime = exp else { return nil }
    return expirationTime.timeIntervalSinceNow
  }

  /// Get a single audience value (useful when there's only one)
  public var singleAudience: String? {
    switch aud {
    case .single(let value):
      return value
    case .multiple(let values):
      return values.first
    case .none:
      return nil
    }
  }

  /// Get all audience values as an array
  public var audienceValues: [String] {
    aud?.values ?? []
  }
}

extension JWT.Payload.Audience {
  /// Get all audience values as an array
  public var values: [String] {
    switch self {
    case .single(let value):
      return [value]
    case .multiple(let values):
      return values
    }
  }

  /// Check if a specific audience is included
  public func contains(_ audience: String) -> Bool {
    values.contains(audience)
  }
}

extension JWT.Payload {
  /// Get a claim value with a more intuitive name
  public func claim<T>(_ key: String, as type: T.Type = T.self) -> T? {
    additionalClaim(key, as: type)
  }

  /// Get a claim value or a default
  public func claim<T>(_ key: String, default defaultValue: T) -> T {
    additionalClaim(key, as: T.self) ?? defaultValue
  }

  /// Check if a claim exists
  public func hasClaim(_ key: String) -> Bool {
    // Check standard claims first
    switch key {
    case "iss": return iss != nil
    case "sub": return sub != nil
    case "aud": return aud != nil
    case "exp": return exp != nil
    case "nbf": return nbf != nil
    case "iat": return iat != nil
    case "jti": return jti != nil
    default:
      // For additional claims, we need to check if the claim exists
      // Since additionalClaim returns nil for non-existent claims with proper types
      return additionalClaim(key, as: String.self) != nil
        || additionalClaim(key, as: Int.self) != nil || additionalClaim(key, as: Bool.self) != nil
        || additionalClaim(key, as: Double.self) != nil
        || additionalClaim(key, as: [String].self) != nil
        || additionalClaim(key, as: [String: Any].self) != nil
    }
  }

  /// Get all standard claim keys
  public var standardClaimKeys: [String] {
    var keys: [String] = []
    if iss != nil { keys.append("iss") }
    if sub != nil { keys.append("sub") }
    if aud != nil { keys.append("aud") }
    if exp != nil { keys.append("exp") }
    if nbf != nil { keys.append("nbf") }
    if iat != nil { keys.append("iat") }
    if jti != nil { keys.append("jti") }
    return keys
  }
}

extension JWT {
  /// Quick check if a token is valid (signature + not expired)
  public func isValid(with key: VerificationKey) -> Bool {
    do {
      return try verifyAndValidate(with: key)
    } catch {
      return false
    }
  }

  /// Get validation errors if any
  public func validationErrors(with key: VerificationKey) -> [String] {
    var errors: [String] = []

    // Check signature
    do {
      let signatureValid = try verify(with: key)
      if !signatureValid {
        errors.append("Invalid signature")
      }
    } catch {
      errors.append("Signature verification failed: \(error)")
    }

    // Check expiration
    if payload.isExpired {
      errors.append("Token is expired")
    }

    // Check not before
    if payload.isNotYetValid {
      errors.append("Token is not yet valid")
    }

    return errors
  }
}
