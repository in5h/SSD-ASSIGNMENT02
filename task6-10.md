# ASSIGNMENT 03: API SECURITY  
**Course:** CY4001 – Secure Software Design  

---

## Submitted By
- **Sajer Tasleem (22I-1677)**  
- **Fatima Babar (22I-1565)**  
- **Insharah Aman (22I-1653)**  
- **Zujajah Usman (22I-1733)**  
- **Aneeqa Mehboob (22I-7446)**  

**Submitted To:** Dr. Nabeel Ahmad  
**Deadline:** 26th October, 2025  

---

## Introduction
This document outlines the vulnerabilities identified in the **Secure Banking API** and details the fixes implemented to mitigate them.  
Each task focuses on addressing specific **OWASP Top 10 API** vulnerabilities related to authentication, authorization, input validation, and secure error handling.

### Project Objectives
- Eliminate unsafe coding practices  
- Ensure secure handling of user data  
- Implement rate limiting and access control  
- Prevent mass assignment and data exposure  
- Enforce strong JWT authentication  
- Strengthen input validation and exception handling  

---

## Identified Vulnerabilities and Fix Summary

| Task No. | Vulnerability | Description | Status |
|-----------|----------------|--------------|---------|
| 6 | Mass Assignment | Role escalation via API payloads | ✅ Fixed |
| 7 | Weak JWT Implementation | Long expiry, static secret, no validation | ✅ Fixed |
| 8 | Detailed Error Messages | Information leakage via stack traces | ✅ Fixed |
| 9 | Input Validation | Unvalidated and negative transfer amounts | ✅ Fixed |
| 10 | Lack of Integration Tests | Missing security regression validation | ✅ Fixed |

---

## 🔒 Fix No. 6: Prevent Mass Assignment
**Vulnerability:**  
Users could set their own `role` or `isAdmin` fields during signup, allowing privilege escalation.  

**Solution:**  
Implemented a **SignupRequest DTO** that omits sensitive fields, ensuring safe defaults are assigned by the backend.  

**Files Modified:**
- `SignupRequest.java` *(New)* – excludes `role` and `isAdmin`
- `AuthController.java` – hardcodes role as `"USER"`
- `UserController.java` – enforces user-level role defaults  

**Security Impact:**
- Prevents privilege escalation  
- Ensures roles are controlled only by administrators  
- Eliminates risk of field manipulation in signup payloads  

---

## 🔐 Fix No. 7: JWT Hardening (OWASP API #8)
**Vulnerability:**  
Weak JWT secret key (`"secret123"`), overly long token TTL (30 days), and no issuer/audience validation.  

**Solution:**  
Enhanced JWT configuration with robust validation and cryptographic practices.  

**Files Modified:**
- `JwtService.java` – added issuer/audience claims and secret key management  
- `SecurityConfig.java` – implemented strict token validation  
- `application.properties` – updated with 256-bit secret and 1-hour TTL  

**Security Impact:**
- Strong cryptographic key management (HS256, 256-bit secret)  
- Tokens expire in 1 hour instead of 30 days  
- Validates issuer and audience to ensure authenticity  
- Resists replay and tampering attacks  

---

## 🧱 Fix No. 8: Reduce Error Detail & Add Exception Mapping
**Vulnerability:**  
Detailed stack traces and internal errors were returned in production, leaking sensitive information.  

**Fix Implemented:**  
Created a centralized **GlobalExceptionHandler** using `@ControllerAdvice` and `@ExceptionHandler`.  

- Logs full stack traces internally  
- Returns sanitized, generic messages to users  
- Handles validation errors (`MethodArgumentNotValidException`) gracefully  
- Differentiates between production and development verbosity  

**Files Modified:**
- `GlobalExceptionHandler.java` *(New)*  

**Security Impact:**
- Prevents leakage of internal details (SQL errors, class names)  
- Provides consistent error responses across APIs  
- Complies with OWASP API9: Improper Error Handling  

---

## 🧮 Fix No. 9: Add Input Validation
**Vulnerability:**  
Transfer APIs accepted negative or extremely large numeric values, risking overflow or abuse.  

**Fix Implemented:**  
Added **Bean Validation (JSR-380)** annotations and server-side checks.  

**Key Annotations:**
- `@DecimalMin("0.01")`
- `@DecimalMax("1000000.00")`
- `@NotNull` for required fields  

**Controller Updates:**
- Applied `@Valid` to trigger validation automatically  
- Added logical checks in service layer for suspicious amounts  

**Security Impact:**
- Prevents tampering and financial abuse  
- Strengthens data integrity  
- Complies with OWASP API8: Injection & Data Validation  

---

## 🧪 Fix No. 10: Integration Tests
**Goal:**  
Validate that all implemented security fixes remain effective and resistant to regression.  

**Fix Implemented:**  
Created **Spring Boot integration tests** using `MockMvc` to simulate real API requests.  

**Test Coverage:**
- Authentication & authorization enforcement  
- Input validation for transfers  
- Sanitized error responses  
- Rate limiting and ownership enforcement  

**Security Impact:**
- Provides continuous security assurance  
- Prevents reintroduction of vulnerabilities  
- Strengthens CI/CD pipeline quality gates  

---

## ✅ Conclusion
All identified vulnerabilities have been mitigated using secure coding practices aligned with **OWASP API Security Top 10 (2023)** and **Spring Boot security standards**.  
The system now ensures:

- Strong authentication and authorization  
- Minimal data exposure  
- Robust input validation and rate limiting  
- Secure, consistent error handling  

---

## 📚 References
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)  
- [Spring Security Documentation](https://spring.io/projects/spring-security)  
- [Bucket4j Rate Limiting Library](https://bucket4j.com/)  
- [Oracle Java Secure Coding Guidelines](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
