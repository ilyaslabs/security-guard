package io.github.ilyaslabs.microservice.security.guard;

/**
 * Contains constants used for handling JSON Web Tokens (JWT) in the application.
 * These constants are utilized primarily for claims processing and validation within JWTs.
 */
public class JwtConstants {

    /**
     * Represents the claim key used for specifying the scope in a JSON Web Token (JWT).
     * This constant is used to parse or validate the scope information
     * embedded within the token.
     */
    public static final String KEY_SCOPE_CLAIM = "scope";
}
