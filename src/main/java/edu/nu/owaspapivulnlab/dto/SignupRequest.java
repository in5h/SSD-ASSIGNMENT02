package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * SECURITY FIX #6: Mass Assignment Prevention DTO
 * 
 * This DTO is used for user registration requests. It explicitly defines
 * the fields that can be provided by the client during signup, preventing
 * Mass Assignment vulnerabilities (OWASP API Security Top 10 #6).
 * 
 * Security features:
 * - Only allows username, password, and email fields
 * - Intentionally excludes role and isAdmin fields to prevent privilege escalation
 * - Controllers will hardcode role="USER" and isAdmin=false
 * 
 * Changes made:
 * - Created explicit DTO without sensitive fields (role, isAdmin)
 * - Added validation constraints for input validation
 * - Prevents clients from setting their own role or admin status
 */
@Data
public class SignupRequest {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
    
    @Email(message = "Email must be valid")
    @NotBlank(message = "Email is required")
    private String email;
}
