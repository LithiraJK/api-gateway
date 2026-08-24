package com.tripvisito.apigateway.filter;

import com.tripvisito.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Global JWT Authentication Filter for the Tripvisito API Gateway.
 *
 * <p>This filter intercepts every incoming request before it is routed to a
 * downstream service. It enforces the following policy:
 *
 * <ul>
 *   <li>Requests matching a <b>fully public</b> path (e.g. login, register,
 *       Stripe webhook) are forwarded without any token check.</li>
 *   <li>Requests to <b>read-only public</b> paths (e.g. listing all trips,
 *       viewing a trip by ID, viewing trip reviews) are forwarded without
 *       auth when the HTTP method is {@code GET}.</li>
 *   <li>All other requests require a valid {@code Authorization: Bearer <token>}
 *       header. If missing or invalid, the filter responds immediately with
 *       {@code 401 Unauthorized} and never forwards to a downstream service.</li>
 *   <li>On successful validation, the filter mutates the forwarded request to
 *       include user-identity headers ({@code X-User-Id}, {@code X-User-Name},
 *       {@code X-User-Email}, {@code X-User-Roles}) so downstream services
 *       can read user context without needing their own JWT logic.</li>
 * </ul>
 *
 * <p><b>Threading model:</b> This runs on Netty's event-loop — all operations
 * must be non-blocking. No blocking calls (JDBC, synchronous HTTP, etc.) are
 * made here; JWT parsing is pure in-memory CPU work and is safe to call on
 * the event loop.
 *
 * @author Tripvisito ECA Team
 */
@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // ── Public Route Definitions ────────────────────────────────────────────

    /**
     * Paths that are fully public for ALL HTTP methods (no JWT needed).
     * Matches exact paths or Ant-style patterns.
     */
    private static final List<String> FULLY_PUBLIC_PATHS = List.of(
            // Auth endpoints (no token needed to obtain a token!)
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/google-login",
            "/api/v1/auth/refresh",

            // Stripe webhook — must receive raw body from Stripe (no auth header)
            "/api/v1/payment/stripe-webhook"
    );

    /**
     * Paths that are public for GET requests only.
     * Uses Ant-style patterns — "/**" matches any suffix.
     */
    private static final List<String> PUBLIC_GET_PATTERNS = List.of(
            "/api/v1/trip/all",          // GET all trips (paginated)
            "/api/v1/trip/*",            // GET trip by ID  (single segment wildcard)
            "/api/v1/reviews/*"          // GET reviews for a specific trip
    );

    // ── Filter Logic ────────────────────────────────────────────────────────

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path   = exchange.getRequest().getURI().getPath();
        final String method = exchange.getRequest().getMethod().name();

        // 0. Pass-through: preflight OPTIONS requests (required for CORS)
        if ("OPTIONS".equalsIgnoreCase(method)) {
            log.debug("[Gateway] OPTIONS preflight request — skipping auth: {}", path);
            return chain.filter(exchange);
        }

        // 1. Pass-through: fully public paths (all methods)
        boolean isFullyPublic = FULLY_PUBLIC_PATHS.stream()
                .anyMatch(p -> PATH_MATCHER.match(p, path));
        if (isFullyPublic) {
            log.debug("[Gateway] Public path — skipping auth: {} {}", method, path);
            return chain.filter(exchange);
        }

        // 2. Pass-through: public GET-only paths
        boolean isPublicGet = "GET".equalsIgnoreCase(method)
                && !"/api/v1/trip/user-trips".equalsIgnoreCase(path)
                && !"/api/v1/reviews/user".equalsIgnoreCase(path)
                && PUBLIC_GET_PATTERNS.stream()
                        .anyMatch(pattern -> PATH_MATCHER.match(pattern, path));
        if (isPublicGet) {
            log.debug("[Gateway] Public GET path — skipping auth: {}", path);
            return chain.filter(exchange);
        }

        // 3. All other requests → require a valid Bearer token
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("[Gateway] Missing or malformed Authorization header for: {} {}", method, path);
            return rejectUnauthorized(exchange, "Missing or malformed Authorization header");
        }

        String token = authHeader.substring(7); // strip "Bearer "

        try {
            Claims claims = jwtUtil.extractAllClaims(token);

            // Extract identity from JWT claims
            String userId = claims.getSubject();                               // "sub"
            String name   = getClaimOrEmpty(claims, "name");
            String email  = getClaimOrEmpty(claims, "email");
            String profileImg = getClaimOrEmpty(claims, "profileImg");
            String roles  = getClaimOrEmpty(claims, "roles");                 // e.g. "[USER]"

            log.debug("[Gateway] Authenticated userId={} roles={} → {} {}",
                    userId, roles, method, path);

            // Mutate the forwarded request — add user-identity headers for downstream services.
            // Downstream services read these headers instead of parsing JWT themselves.
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id",    userId)
                    .header("X-User-Name",  name)
                    .header("X-User-Email", email)
                    .header("X-User-Profile-Img", profileImg)
                    .header("X-User-Roles", roles)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("[Gateway] Expired JWT for path: {}", path);
            return rejectUnauthorized(exchange, "Token has expired");

        } catch (Exception e) {
            log.warn("[Gateway] Invalid JWT for path {}: {}", path, e.getMessage());
            return rejectUnauthorized(exchange, "Invalid token");
        }
    }

    /**
     * Runs at order {@code -1} — executes before all other gateway filters
     * (including built-in route predicates) so that rejected requests never
     * reach a downstream service.
     */
    @Override
    public int getOrder() {
        return -1;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Writes a JSON 401 response and terminates the exchange without forwarding.
     */
    private Mono<Void> rejectUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
                {"status":401,"error":"Unauthorized","message":"%s"}
                """.formatted(message);

        var buffer = response.bufferFactory().wrap(body.getBytes());
        return response.writeWith(Mono.just(buffer));
    }

    /**
     * Safely extracts a String claim, returning an empty string if absent.
     */
    private String getClaimOrEmpty(Claims claims, String claimKey) {
        Object value = claims.get(claimKey);
        return value != null ? value.toString() : "";
    }
}
