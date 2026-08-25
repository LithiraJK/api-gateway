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

        // Inject default headers:
        String userId = "1";
        String userName = "Super Admin";
        String userEmail = "admin@tripvisito.com";
        String userProfileImg = "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?auto=format&fit=facearea&facepad=2&w=256&h=256&q=80";
        String userRoles = "ROLE_ADMIN,ROLE_SUPERADMIN,ROLE_USER";

        log.info("[Gateway Filter] Forwarding with default headers: userId={}, roles={}", userId, userRoles);

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

    @Override
    public int getOrder() {
        return -1;
    }
}
