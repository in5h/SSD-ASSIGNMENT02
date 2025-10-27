package edu.nu.owaspapivulnlab.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SECURITY FIX #4: Data Transfer Object (DTO) for User Data
 * 
 * This DTO controls data exposure by only including safe fields in API responses.
 * It addresses OWASP API Security Top 10 #3: Excessive Data Exposure.
 * 
 * Changes made:
 * - Created UserDto to replace direct AppUser entity exposure
 * - Excluded sensitive fields: password, role, isAdmin
 * - Only exposes: id, username, email (safe public information)
 * - Prevents accidental exposure of internal user data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String username;
    private String email;
    // Note: password, role, and isAdmin are intentionally excluded for security
}
