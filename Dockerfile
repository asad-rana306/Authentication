# Multi-stage build for a lean production image
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace

# Copy sources and build the executable jar
COPY pom.xml mvnw ./
COPY .mvn .mvn
COPY src src
RUN chmod +x mvnw && ./mvnw -q -DskipTests package
RUN JAR_FILE=$(ls target/*.jar | grep -v '\.original$' | head -n 1) && cp "$JAR_FILE" app.jar

FROM eclipse-temurin:21-jre
WORKDIR /app

# Run as non-root user for better security
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

COPY --from=build /workspace/app.jar /app/app.jar

EXPOSE 8080
ENV JAVA_OPTS=""
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]

