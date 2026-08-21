package com.tripvisito.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Stateless JWT utility for the API Gateway.
 *
 * <p>This class is ONLY responsible for VALIDATING tokens — it never issues
 * them. Token issuance is the responsibility of the {@code user-service}.
 *
 * <p>The secret key must be identical to the one used by {@code user-service}
 * when signing tokens. It is injected from the {@code jwt.secret} property,
 * which is sourced from the config-server ({@code api-gateway.yml}).
 *
 * <p>Uses JJWT 0.12.x API ({@link Jwts#parser()} builder pattern).
 */
@Component
public class JwtUtil {

    /**
     * HMAC-SHA secret key value. Must be at least 32 characters for HS256.
     * Resolved from: config-server → api-gateway.yml → jwt.secret
     * Falls back to the environment variable JWT_SECRET.
     */
    @Value("${jwt.secret}")
    private String secret;

    // ── Key Construction ────────────────────────────────────────────────────

    /**
     * Builds a {@link SecretKey} from the raw secret string.
     * Called lazily on each parse so the key reflects the latest injected value.
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Parses and validates the given JWT, returning all claims.
     *
     * @param token the raw Bearer token (without "Bearer " prefix)
     * @return all {@link Claims} embedded in the token
     * @throws ExpiredJwtException      if the token has expired
     * @throws MalformedJwtException    if the token is structurally invalid
     * @throws SignatureException       if the signature does not match
     * @throws UnsupportedJwtException  if the JWT format is not supported
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Returns {@code true} if the token is cryptographically valid and not expired.
     * Used by {@link com.tripvisito.apigateway.filter.JwtAuthFilter} as a fast-path check.
     */
    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts the subject claim (user ID) from a validated token.
     * Downstream services receive this as the {@code X-User-Id} header.
     */
    public String extractUserId(String token) {
        return extractAllClaims(token).getSubject();
    }
}
