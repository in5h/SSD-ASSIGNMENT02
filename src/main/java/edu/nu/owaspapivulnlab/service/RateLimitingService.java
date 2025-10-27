package edu.nu.owaspapivulnlab.service;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import io.github.bucket4j.Bandwidth;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURITY FIX #5: Rate Limiting Service
 * 
 * This service implements rate limiting using Bucket4j to prevent abuse of sensitive endpoints.
 * It addresses OWASP API Security Top 10 #4: Unrestricted Resource Consumption.
 * 
 * Changes made:
 * - Added Bucket4j dependency for token bucket rate limiting
 * - Configured 10 requests per minute limit for sensitive operations
 * - Provides per-user rate limiting using username as key
 * - Used ConcurrentHashMap for thread-safe bucket storage
 */
@Service
public class RateLimitingService {
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    
    // Rate limit: 10 requests per minute for sensitive operations
    // This prevents brute force attacks and resource exhaustion
    private final Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1)));
    
    /**
     * Get or create a rate limiting bucket for a specific user
     * @param key The user identifier (typically username)
     * @return Bucket instance for rate limiting
     */
    public Bucket getBucket(String key) {
        return buckets.computeIfAbsent(key, k -> Bucket4j.builder()
                .addLimit(limit)
                .build());
    }
    
    /**
     * Check if a request is allowed for the given user
     * @param key The user identifier
     * @return true if request is allowed, false if rate limit exceeded
     */
    public boolean isAllowed(String key) {
        Bucket bucket = getBucket(key);
        return bucket.tryConsume(1);
    }
}
