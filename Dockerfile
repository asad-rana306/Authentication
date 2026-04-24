# Force the Intel/AMD64 architecture at the start
FROM --platform=linux/amd64 maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace

# Copy your source code
COPY pom.xml .
COPY src src

# Run the native Maven command
RUN mvn -q -DskipTests package

# Rename the JAR for the next stage
RUN cp target/*.jar app.jar

# Stage 2: Production (also force Intel architecture)
FROM --platform=linux/amd64 eclipse-temurin:21-jre
WORKDIR /app

# Security: Non-root user
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

COPY --from=build /workspace/app.jar /app/app.jar

EXPOSE 8080
ENV JAVA_OPTS=""
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]

#Build: You run docker build -t ranaasad462/iers-fyp:latest .

#Push: You run docker push ranaasad462/iers-fyp:latest