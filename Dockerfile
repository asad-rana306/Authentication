# Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace

# Prime Maven dependency cache before copying sources.
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
RUN chmod +x mvnw && ./mvnw -q -DskipTests dependency:go-offline

COPY src src
RUN ./mvnw -q -DskipTests clean package

# Runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app

# Security: Non-root user
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

COPY --from=build /workspace/target/*SNAPSHOT.jar /app/app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
