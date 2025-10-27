package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    @NotBlank
    private String password; // Now stores BCrypt hashed passwords

    private String role;   // e.g., "USER" or "ADMIN"
    private boolean isAdmin;

    @Email
    private String email;
}
