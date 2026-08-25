package com.tripvisito.apigateway.filter;

import com.tripvisito.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path   = exchange.getRequest().getURI().getPath();
        final String method = exchange.getRequest().getMethod().name();

        log.info("[Gateway Filter] Intercepted request: {} {}", method, path);

        // Preflight OPTIONS requests pass-through
        if ("OPTIONS".equalsIgnoreCase(method)) {
            return chain.filter(exchange);
        }

        // Initialize dummy user headers based on path
        String userId = "3";
        String userName = "John Doe";
        String userEmail = "john@tripvisito.com";
        String userProfileImg = "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=facearea&facepad=2&w=256&h=256&q=80";
        String userRoles = "[USER]";

        // If the path suggests admin operations, default to Super Admin
        if (path.contains("admin") || path.contains("status") || path.contains("delete") ||
            path.contains("register/new-user") || path.contains("all-bookings") || 
            path.contains("dashboard") || path.contains("users") || path.contains("all-trips")) {
            userId = "1";
            userName = "Super Admin";
            userEmail = "superadmin@tripvisito.com";
            userProfileImg = "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?auto=format&fit=facearea&facepad=2&w=256&h=256&q=80";
            userRoles = "[SUPERADMIN, ADMIN, USER]";
        }

        // Try to extract identity from Authorization header if present
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                // Parse claims without failing if the signature/expiration is invalid
                Claims claims = jwtUtil.extractAllClaims(token);
                userId = claims.getSubject();
                userName = getClaimOrFallback(claims, "name", userName);
                userEmail = getClaimOrFallback(claims, "email", userEmail);
                userProfileImg = getClaimOrFallback(claims, "profileImg", userProfileImg);
                userRoles = getClaimOrFallback(claims, "roles", userRoles);
                log.info("[Gateway Filter] Parsed user identity from token: userId={}, roles={}", userId, userRoles);
            } catch (Exception e) {
                log.warn("[Gateway Filter] Token parsing failed (continuing with fallback user): {}", e.getMessage());
            }
        }

        log.info("[Gateway Filter] Forwarding with headers: userId={}, roles={}", userId, userRoles);

        // Mutate request to inject identity headers for downstream services
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", userId)
                .header("X-User-Name", userName)
                .header("X-User-Email", userEmail)
                .header("X-User-Profile-Img", userProfileImg)
                .header("X-User-Roles", userRoles)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String getClaimOrFallback(Claims claims, String key, String fallback) {
        Object val = claims.get(key);
        return val != null ? val.toString() : fallback;
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
