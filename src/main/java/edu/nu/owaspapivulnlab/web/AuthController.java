package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.dto.SignupRequest;
import edu.nu.owaspapivulnlab.dto.UserDto;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.service.PasswordService;

import java.util.HashMap;
import java.util.Map;

/**
 * SECURITY FIX #1: BCrypt Password Hashing and Signup Flow
 * 
 * This controller implements secure authentication with BCrypt password hashing
 * and adds a proper signup flow. It addresses OWASP API Security Top 10 #2: Broken Authentication.
 * 
 * Changes made:
 * - Replaced plaintext password comparison with BCrypt verification
 * - Added signup endpoint with proper password hashing
 * - Added userId to JWT claims for ownership enforcement
 * - Added validation for username/email uniqueness
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordService passwordService; // SECURITY FIX #1: Added BCrypt password service

    public AuthController(AppUserRepository users, JwtService jwt, PasswordService passwordService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordService = passwordService;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    /**
     * SECURITY FIX #1: Secure Login with BCrypt Password Verification
     * - Replaced plaintext password comparison with BCrypt.matches()
     * - Added userId to JWT claims for ownership enforcement
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        AppUser user = users.findByUsername(req.username()).orElse(null);
        // SECURITY FIX #1: Use BCrypt password verification instead of plaintext comparison
        if (user != null && passwordService.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            claims.put("userId", user.getId()); // SECURITY FIX #3: Add userId for ownership checks
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    /**
     * SECURITY FIX #1: Secure Signup with BCrypt Password Hashing
     * - Added proper signup endpoint with password hashing
     * - Added validation for username/email uniqueness
     * - Returns UserDto to prevent data exposure
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        // Check if username already exists
        if (users.findByUsername(req.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "username already exists");
            return ResponseEntity.status(400).body(error);
        }
        
        // Check if email already exists
        if (users.findByEmail(req.getEmail()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "email already exists");
            return ResponseEntity.status(400).body(error);
        }
        
        // Create new user with hashed password
        // SECURITY FIX #6: Hardcode safe defaults - prevent mass assignment of role/isAdmin
        AppUser newUser = AppUser.builder()
                .username(req.getUsername())
                .password(passwordService.encodePassword(req.getPassword())) // SECURITY FIX #1: Hash password with BCrypt
                .email(req.getEmail())
                .role("USER") // SECURITY FIX #6: Default role, not assignable by client
                .isAdmin(false) // SECURITY FIX #6: Default admin status, not assignable by client
                .build();
        
        AppUser savedUser = users.save(newUser);
        
        // Return user DTO without sensitive information
        UserDto userDto = UserDto.builder()
                .id(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .build();
        
        return ResponseEntity.ok(userDto);
    }
}
