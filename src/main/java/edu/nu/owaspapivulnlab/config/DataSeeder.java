package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.PasswordService;

/**
 * SECURITY FIX #1: BCrypt Password Hashing for Seed Data
 * 
 * This configuration seeds the database with initial users using BCrypt hashed passwords.
 * It addresses OWASP API Security Top 10 #2: Broken Authentication.
 * 
 * Changes made:
 * - Updated to use PasswordService for BCrypt password hashing
 * - Replaced plaintext passwords with properly hashed ones
 * - Maintains existing user accounts but with secure password storage
 */
@Configuration
public class DataSeeder {
    /**
     * SECURITY FIX #1: Seed users with BCrypt hashed passwords
     * - Uses PasswordService to hash passwords instead of storing plaintext
     * - Maintains existing alice/bob users but with secure password storage
     */
    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordService passwordService) {
        return args -> {
            if (users.count() == 0) {
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(passwordService.encodePassword("alice123"))
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build());
                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(passwordService.encodePassword("bob123"))
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build());
                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}
