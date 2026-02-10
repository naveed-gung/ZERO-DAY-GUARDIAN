FROM eclipse-temurin:21-jdk AS builder

WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle/ gradle/
COPY gradlew ./
RUN chmod +x gradlew

# Download dependencies first (cacheable layer)
RUN ./gradlew dependencies --no-daemon || true

COPY src/ src/
RUN ./gradlew bootJar --no-daemon -x test

# --- Runtime stage ---
FROM eclipse-temurin:21-jre

RUN groupadd -r guardian && useradd -r -g guardian -s /sbin/nologin guardian

WORKDIR /app
COPY --from=builder /build/build/libs/*.jar app.jar

RUN chown -R guardian:guardian /app

USER guardian

EXPOSE 8080
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["sh", "-c", "wget -qO- http://localhost:8081/actuator/health || exit 1"]

ENTRYPOINT ["java", \
    "-XX:+UseG1GC", \
    "-XX:MaxGCPauseMillis=50", \
    "-XX:+UseStringDeduplication", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]
