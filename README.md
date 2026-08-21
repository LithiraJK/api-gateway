# Tripvisito - API Gateway

## Mandatory Student & GCP Information
- **Student Name:** Lithira Jayanaka
- **Student Number:** 241722002
- **GCP Project ID:** project-a4f7bad0-3923-4cdb-b9b

---

## Project Description
The **API Gateway** acts as the entry point for all frontend client traffic to the Tripvisito backend platform. It handles routing and forwards HTTP requests to logical microservices registered in Eureka. Additionally, it contains a global security filter (`JwtAuthFilter`) to intercept requests, validate JWT signatures, and propagate user context (like `X-User-Id` headers) downstream, securing the backend.

## Technology Stack
- **Runtime:** Java 25
- **Framework:** Spring Boot (v3+) & Spring Cloud Gateway (Reactive)
- **Security:** Spring Security (Reactive) & JWT Verification
- **Build Tool:** Maven

## Setup / Getting Started Instructions

### Prerequisites
- JDK 25 installed and configured
- Maven 3+

### Local Setup
1. Navigate to the service folder:
   ```bash
   cd tripvisito-springboot/platform-services/api-gateway
   ```
2. Build the project:
   ```bash
   mvn clean package -DskipTests
   ```
3. Run the API Gateway:
   ```bash
   mvn spring-boot:run
   ```
   The service runs on port `8080` (routes calls via `http://localhost:8080/api/v1/*`).

### Process Management (PM2 Deployment)
On the GCP VM Instance (IaaS):
```bash
pm2 start ecosystem.config.js --only api-gateway
```
Persists process execution and restarts automatically on VM reboots.
