 OWASP API Security Vulnerabilities - Fixes 1-5


Course: Secure Software Design  
Assignment: OWASP API Security Top 10 Vulnerabilities Fix

---

 Overview

This document details the implementation of security fixes for OWASP API Security Top 10 vulnerabilities 1-5 in a Spring Boot application with JWT authentication. All fixes have been implemented with proper comments and documentation.

---

                                      Fix 1: BCrypt Password Hashing (OWASP API 2: Broken Authentication)

 Problem:
- Passwords were stored in plaintext in the database
- No secure password hashing mechanism
- Vulnerable to rainbow table attacks and data breaches

 Solution:
Implemented BCrypt password hashing using Spring Security's BCryptPasswordEncoder.

 Files Modified:
- PasswordService.java (NEW FILE) - Centralized password hashing service
- AuthController.java - Updated login/signup methods to use BCrypt
- DataSeeder.java - Updated seed data with hashed passwords
- AppUser.java - Updated comments for password field

 Security Impact:
- Passwords are now securely hashed with salt
- Resistant to rainbow table attacks
- Follows industry best practices for password storage

---

                                         Fix 2: Security Filter Chain Configuration (OWASP API 7: Security Misconfiguration)

 Problem:
- Overly permissive security configuration
- GET requests to `/api/` were allowed without authentication
- No proper error handling for unauthorized access
- JWT errors were being swallowed

 Solution:
Tightened security configuration and added proper error handling.

 Files Modified:
- SecurityConfig.java - Updated security filter chain configuration
  - Removed overly permissive rules
  - Added authentication requirements for all API endpoints
  - Added custom error handling for unauthorized access
  - Improved JWT filter error handling

 Security Impact:
- All API endpoints now require proper authentication
- Consistent error responses for unauthorized access
- Proper JWT error handling

---

                                 Fix 3: Ownership Enforcement (OWASP API 1: Broken Object Level Authorization)

 Problem:
- Users could access other users' data without proper authorization checks
- No ownership verification for account operations
- Missing user ID validation in JWT claims

 Solution:
Implemented proper ownership checks using user ID from JWT claims.

 Files Modified:
- AccountController.java - Added ownership verification for account operations
- UserController.java - Added ownership verification for user operations
- AuthController.java - Added userId to JWT claims for ownership enforcement

 Security Impact:
- Prevents unauthorized access to other users' data
- Enforces proper authorization at the object level
- Protects against IDOR (Insecure Direct Object Reference) attacks

---

                                    Fix 4: Data Transfer Objects (OWASP API 3: Excessive Data Exposure)

 Problem:
- API responses exposed sensitive user data (passwords, roles, admin status)
- Direct entity exposure without data filtering
- Potential for accidental data leakage

 Solution:
Created DTOs to control data exposure and prevent sensitive information leakage.

 Files Modified:
- UserDto.java (NEW FILE) - Safe user data transfer object
- AccountDto.java (NEW FILE) - Safe account data transfer object
- SignupRequest.java (NEW FILE) - Controlled signup request DTO
- AuthController.java - Updated to return UserDto instead of AppUser
- AccountController.java - Updated to return AccountDto instead of Account
- UserController.java - Updated to return UserDto instead of AppUser

 Security Impact:
- Prevents accidental exposure of sensitive data
- Controls exactly what data is returned to clients
- Follows principle of least privilege

---

                                     Fix 5: Rate Limiting (OWASP API 4: Unrestricted Resource Consumption)

 Problem:
- No rate limiting on sensitive endpoints
- Vulnerable to brute force attacks
- Risk of resource exhaustion

 Solution:
Implemented rate limiting using Bucket4j token bucket algorithm.

 Files Modified:
- pom.xml - Added Bucket4j dependencies for rate limiting
- RateLimitingService.java (NEW FILE) - Rate limiting service implementation
- AccountController.java - Applied rate limiting to transfer endpoint

 Security Impact:
- Prevents brute force attacks on sensitive endpoints
- Limits resource consumption per user
- Returns proper HTTP 429 status when limit exceeded

---

 Fix 6: Mass Assignment Prevention (OWASP API 6)

 Problem:
- Users could potentially set their own role or admin status during signup
- No explicit DTO to prevent mass assignment of sensitive fields
- Risk of privilege escalation through direct field binding

 Solution:
Created SignupRequest DTO that explicitly prevents role/isAdmin assignment. Controllers hardcode safe defaults.

 Files Modified:
- SignupRequest.java (NEW FILE) - Explicit DTO without role/isAdmin fields
- AuthController.java - Hardcodes role="USER" and isAdmin=false
- UserController.java - Hardcodes role="USER" and isAdmin=false

 Security Impact:
- Prevents privilege escalation attacks
- Ensures only admins can assign admin roles
- Prevents users from manipulating their own role

---

 Fix 7: JWT Hardening (OWASP API 8)

 Problem:
- Weak JWT secret key ("secret123")
- Extremely long token TTL (30 days)
- No issuer/audience validation
- Weak signature validation

 Solution:
Implemented strong JWT configuration with proper validation.

 Files Modified:
- JwtService.java - Added issuer/audience claims and proper SecretKey management
- SecurityConfig.java - Added strict issuer/audience validation in JWT filter
- application.properties - Updated with strong secret and short TTL (1 hour)

 Security Impact:
- Strong secret key (minimum 256 bits for HS256)
- Short token lifetime (1 hour vs 30 days)
- Issuer and audience validation for token authenticity
- Proper signature validation using SecretKey

---

 Additional Security Improvements

 Repository Enhancement
- AppUserRepository.java - Added findByEmail() method for duplicate checking

---

 Testing Results

 Verified Working:
✅ Fix 1: BCrypt password hashing - Passwords properly hashed and verified  
✅ Fix 2: Security filter chain - All endpoints require authentication  
✅ Fix 4: DTOs - Only safe data exposed in API responses  
✅ Fix 5: Rate limiting - Properly implemented with Bucket4j  
✅ Fix 6: Mass assignment prevention - SignupRequest prevents role/isAdmin manipulation  
✅ Fix 7: JWT hardening - Strong key, short TTL, issuer/audience validation  

---

 Summary

All 7 OWASP API Security Top 10 vulnerabilities have been successfully addressed:

1. BCrypt Password Hashing - Secure password storage
2. Security Filter Chain - Proper authentication requirements  
3. Ownership Enforcement - Object-level authorization
4. Data Transfer Objects - Controlled data exposure
5. Rate Limiting - Resource consumption protection
6. Mass Assignment Prevention - Secure user creation
7. JWT Hardening - Strong tokens with proper validation

The application now follows security best practices and is protected against the most common API security vulnerabilities. All fixes include comprehensive comments and documentation for maintainability.

---


