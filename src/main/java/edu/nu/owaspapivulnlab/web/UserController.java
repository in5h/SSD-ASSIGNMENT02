package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.dto.SignupRequest;
import edu.nu.owaspapivulnlab.dto.UserDto;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.PasswordService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SECURITY FIX #3 & #4: Ownership Enforcement and DTOs for User Data
 * 
 * This controller implements proper ownership checks and uses DTOs to control data exposure.
 * It addresses OWASP API Security Top 10 #1: Broken Object Level Authorization and #3: Excessive Data Exposure.
 * 
 * Changes made:
 * - Added ownership verification for user operations
 * - Added role-based access control for admin functions
 * - Returns UserDto instead of AppUser entity
 * - Added proper validation and error handling
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordService passwordService; // SECURITY FIX #1: Added BCrypt password service

    public UserController(AppUserRepository users, PasswordService passwordService) {
        this.users = users;
        this.passwordService = passwordService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        // Users can only access their own profile
        if (!currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        UserDto userDto = UserDto.builder()
                .id(currentUser.getId())
                .username(currentUser.getUsername())
                .email(currentUser.getEmail())
                .build();
        
        return ResponseEntity.ok(userDto);
    }

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody SignupRequest signupRequest) {
        // Check if username already exists
        if (users.findByUsername(signupRequest.getUsername()).isPresent()) {
            return ResponseEntity.status(400).body(Map.of("error", "username already exists"));
        }
        
        // Check if email already exists
        if (users.findByEmail(signupRequest.getEmail()).isPresent()) {
            return ResponseEntity.status(400).body(Map.of("error", "email already exists"));
        }
        
        // Create new user with hashed password and default role
        // SECURITY FIX #6: Hardcode safe defaults - prevent mass assignment of role/isAdmin
        // SECURITY FIX #1: Hash password with BCrypt
        AppUser newUser = AppUser.builder()
                .username(signupRequest.getUsername())
                .password(passwordService.encodePassword(signupRequest.getPassword())) // SECURITY FIX #1: Hash password
                .email(signupRequest.getEmail())
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

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        // Only allow admins to search users
        if (!"ADMIN".equals(currentUser.getRole())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        List<AppUser> searchResults = users.search(q);
        List<UserDto> userDtos = searchResults.stream()
                .map(user -> UserDto.builder()
                        .id(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .build())
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(userDtos);
    }

    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        // Only allow admins to list all users
        if (!"ADMIN".equals(currentUser.getRole())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        List<AppUser> allUsers = users.findAll();
        List<UserDto> userDtos = allUsers.stream()
                .map(user -> UserDto.builder()
                        .id(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .build())
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(userDtos);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        // Users can only delete their own account, admins can delete any account
        if (!currentUser.getId().equals(id) && !"ADMIN".equals(currentUser.getRole())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
