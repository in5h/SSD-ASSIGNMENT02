package edu.nu.owaspapivulnlab.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SECURITY FIX #4: Data Transfer Object (DTO) for Account Data
 * 
 * This DTO controls data exposure by only including safe fields in API responses.
 * It addresses OWASP API Security Top 10 #3: Excessive Data Exposure.
 * 
 * Changes made:
 * - Created AccountDto to replace direct Account entity exposure
 * - Excluded sensitive field: ownerUserId (prevents user enumeration)
 * - Only exposes: id, iban, balance (safe account information)
 * - Prevents accidental exposure of account ownership data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountDto {
    private Long id;
    private String iban;
    private Double balance;
    // Note: ownerUserId is intentionally excluded for security
}
