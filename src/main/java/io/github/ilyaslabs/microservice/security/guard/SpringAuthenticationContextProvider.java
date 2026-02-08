package io.github.ilyaslabs.microservice.security.guard;

import io.github.ilyaslabs.microservice.security.guard.model.AuthenticationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Provides the authentication context of the current security request within a Spring-based
 * application. This class implements the AuthenticationContextProvider interface and interacts
 * with the Spring SecurityContext to extract the user's authentication details.
 *
 * It ensures that the authentication context is retrieved from the SecurityContextHolder, and
 * encapsulates the logic to return the appropriate AuthenticationContext object, or handle
 * cases where no authentication context is present.
 */
public class SpringAuthenticationContextProvider implements AuthenticationContextProvider {

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticationContext current() {
        return currentOptional()
                .orElseThrow(() -> new IllegalStateException("No authentication context found"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<AuthenticationContext> currentOptional() {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof AuthenticationContext ctx) {
            return Optional.of(ctx);
        }

        return Optional.empty();
    }
}
