package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.dto.AccountDto;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.RateLimitingService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SECURITY FIX #3 & #5: Ownership Enforcement and Rate Limiting
 * 
 * This controller implements proper ownership checks and rate limiting.
 * It addresses OWASP API Security Top 10 #1: Broken Object Level Authorization and #4: Unrestricted Resource Consumption.
 * 
 * Changes made:
 * - Added ownership verification for all account operations
 * - Added rate limiting to sensitive endpoints (transfers)
 * - Added input validation for transfer amounts
 * - Returns AccountDto to prevent data exposure
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final RateLimitingService rateLimitingService; // SECURITY FIX #5: Added rate limiting

    public AccountController(AccountRepository accounts, AppUserRepository users, RateLimitingService rateLimitingService) {
        this.accounts = accounts;
        this.users = users;
        this.rateLimitingService = rateLimitingService;
    }

    /**
     * SECURITY FIX #3: Ownership Enforcement for Account Balance
     * - Added authentication check
     * - Added ownership verification (users can only access their own accounts)
     * - Returns 403 Forbidden for unauthorized access
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        Account account = accounts.findById(id).orElse(null);
        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }
        
        // SECURITY FIX #3: Enforce ownership - users can only access their own accounts
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        return ResponseEntity.ok(account.getBalance());
    }

    /**
     * SECURITY FIX #3 & #5: Ownership Enforcement and Rate Limiting for Transfers
     * - Added rate limiting to prevent abuse
     * - Added ownership verification
     * - Added input validation for transfer amounts
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        // SECURITY FIX #5: Rate limiting for sensitive operations
        if (!rateLimitingService.isAllowed(auth.getName())) {
            return ResponseEntity.status(429).body(Map.of("error", "Rate limit exceeded"));
        }
        
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        Account account = accounts.findById(id).orElse(null);
        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }
        
        // Enforce ownership - users can only transfer from their own accounts
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        // Input validation
        if (amount <= 0) {
            return ResponseEntity.status(400).body(Map.of("error", "Amount must be positive"));
        }
        
        if (account.getBalance() < amount) {
            return ResponseEntity.status(400).body(Map.of("error", "Insufficient funds"));
        }
        
        account.setBalance(account.getBalance() - amount);
        accounts.save(account);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", account.getBalance());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }
        
        List<Account> userAccounts = accounts.findByOwnerUserId(currentUser.getId());
        List<AccountDto> accountDtos = userAccounts.stream()
                .map(account -> AccountDto.builder()
                        .id(account.getId())
                        .iban(account.getIban())
                        .balance(account.getBalance())
                        .build())
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(accountDtos);
    }
}
