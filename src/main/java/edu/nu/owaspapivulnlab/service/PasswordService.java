package edu.nu.owaspapivulnlab.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * SECURITY FIX #1: BCrypt Password Hashing Service
 * 
 * This service replaces the vulnerable plaintext password storage with BCrypt hashing.
 * BCrypt is a secure password hashing function that includes salt and is resistant to rainbow table attacks.
 * 
 * Changes made:
 * - Added BCryptPasswordEncoder for secure password hashing
 * - Provides encodePassword() method for hashing new passwords
 * - Provides matches() method for verifying passwords during login
 */
@Service
public class PasswordService {
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    
    /**
     * Hash a raw password using BCrypt
     * @param rawPassword The plaintext password to hash
     * @return BCrypt hashed password
     */
    public String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
    
    /**
     * Verify a raw password against a hashed password
     * @param rawPassword The plaintext password to verify
     * @param encodedPassword The BCrypt hashed password to compare against
     * @return true if passwords match, false otherwise
     */
    public boolean matches(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
