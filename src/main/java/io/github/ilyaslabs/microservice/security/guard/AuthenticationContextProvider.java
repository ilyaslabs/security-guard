package io.github.ilyaslabs.microservice.security.guard;

import io.github.ilyaslabs.microservice.security.guard.model.AuthenticationContext;

import java.util.Optional;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
public interface AuthenticationContextProvider {

    /**
     * Retrieves the current authentication context associated with the ongoing request.
     * The authentication context contains security-related details such as the user's
     * unique identifier, granted authorities, and whether the request originated from
     * an API Gateway or was internally generated.
     *
     * @return the current AuthenticationContext instance representing the security
     *         context of the current request.
     */
    AuthenticationContext current();

    /**
     * Retrieves an Optional containing the current authentication context associated
     * with the ongoing request, if available. The authentication context includes
     * information such as the user's unique identifier, granted authorities, and
     * the source of the request (e.g., API Gateway or internal).
     *
     * @return an Optional containing the current AuthenticationContext if present;
     *         otherwise, an empty Optional.
     */
    Optional<AuthenticationContext> currentOptional();
}
