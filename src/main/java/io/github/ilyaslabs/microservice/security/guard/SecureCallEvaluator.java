package io.github.ilyaslabs.microservice.security.guard;

import io.github.ilyaslabs.microservice.security.guard.model.AuthenticationContext;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
public class SecureCallEvaluator {

    public boolean isAllowed(Authentication authentication) {

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticationContext context)) {
            return false;
        }

        return context.isInternalCall();

    }

}
