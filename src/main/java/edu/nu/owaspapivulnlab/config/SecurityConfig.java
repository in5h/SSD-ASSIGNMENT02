package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * SECURITY FIX #2 & #7: Tightened Security Filter Chain Configuration with JWT Hardening
 * 
 * This configuration fixes the overly permissive security settings and implements
 * proper JWT validation with issuer/audience checks. It addresses OWASP API Security Top 10 #7 & #8.
 * 
 * Changes made:
 * - Removed permitAll() on GET /api/** endpoints (was allowing data scraping)
 * - Added authentication requirement for all /api/** endpoints except auth
 * - Added custom authentication entry point for proper error handling
 * - Improved JWT filter with proper error handling and context clearing
 * - Added issuer and audience validation for JWT tokens
 * - Used proper SecretKey for signature validation
 */
@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    /**
     * SECURITY FIX #2: Tightened Security Filter Chain
     * - Removed overly permissive permitAll() rules
     * - Requires authentication for all API endpoints except auth
     * - Added proper error handling for unauthorized access
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated() // All other API endpoints require authentication
                .anyRequest().authenticated()
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console
        
        // Disable default authentication entry point to let our JWT filter handle it
        http.exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Authentication required\"}");
        }));

        http.addFilterBefore(new JwtFilter(secret, issuer, audience), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Improved JWT filter with proper error handling and issuer/audience validation
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        private final String issuer;
        private final String audience;

        JwtFilter(String secret, String issuer, String audience) {
            this.secret = secret;
            this.issuer = issuer;
            this.audience = audience;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    // SECURITY FIX #7: Use proper SecretKey for signature validation
                    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                    
                    Claims c = Jwts.parserBuilder()
                            .setSigningKey(secretKey)
                            .requireIssuer(issuer) // SECURITY FIX #7: Validate issuer claim
                            .requireAudience(audience) // SECURITY FIX #7: Validate audience claim
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                    
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
                            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // Properly handle JWT errors - return 401 for invalid tokens
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Invalid token\"}");
                    return;
                }
            } else {
                // No Authorization header - clear any existing authentication
                SecurityContextHolder.clearContext();
            }
            chain.doFilter(request, response);
        }
    }
}
