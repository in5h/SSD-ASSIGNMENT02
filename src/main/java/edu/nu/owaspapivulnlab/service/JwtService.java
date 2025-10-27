package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

/**
 * SECURITY FIX #7: JWT Hardening
 * 
 * This service implements secure JWT creation with proper security controls.
 * It addresses OWASP API Security Top 10 #8: Broken User Authentication.
 * 
 * Changes made:
 * - Strong secret key from environment variable (minimum 256 bits for HS256)
 * - Short TTL (reduced from 30 days to 1 hour)
 * - Added issuer and audience claims for better token validation
 * - Proper key management using SecretKey
 */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    /**
     * SECURITY FIX #7: Hardened JWT creation with issuer/audience and strong key
     * - Uses strong secret key (minimum 256 bits for HS256)
     * - Short TTL for reduced token lifetime
     * - Added issuer and audience claims for validation
     * - Proper key management with SecretKey
     */
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        
        // SECURITY FIX #7: Use proper SecretKey with minimum 256 bits for HS256
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuer(issuer) // SECURITY FIX #7: Add issuer claim for validation
                .setAudience(audience) // SECURITY FIX #7: Add audience claim for validation
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .signWith(secretKey) // SECURITY FIX #7: Use proper SecretKey instead of raw bytes
                .compact();
    }
}
