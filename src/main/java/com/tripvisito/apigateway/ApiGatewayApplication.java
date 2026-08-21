package com.tripvisito.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Tripvisito API Gateway
 *
 * <p>The single entry-point for the React frontend. Built on Spring Cloud
 * Gateway (WebFlux/Netty — reactive, non-blocking). Responsibilities:
 *
 * <ul>
 *   <li><b>Routing:</b> Forwards requests to downstream services discovered
 *       via Eureka using {@code lb://} (load-balanced) URIs.</li>
 *   <li><b>Auth:</b> A global {@link com.tripvisito.apigateway.filter.JwtAuthFilter}
 *       validates JWTs on every protected route, then propagates user identity
 *       as {@code X-User-Id}, {@code X-User-Name}, {@code X-User-Email},
 *       and {@code X-User-Roles} headers to downstream services so they
 *       do NOT need their own JWT verification logic.</li>
 *   <li><b>CORS:</b> Centralised CORS policy for the React dev origin
 *       (http://localhost:5173) and production domain.</li>
 * </ul>
 *
 * <p><b>Startup order:</b> Start last (7th), after all business services
 * have registered on Eureka so routes resolve immediately.
 *
 * <p><b>Port:</b> 8080
 *
 * @author Tripvisito ECA Team
 */
@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
