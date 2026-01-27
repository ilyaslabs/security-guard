package io.github.ilyaslabs.microservice.security.guard.model;

import org.bson.types.ObjectId;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * Represents the authentication context for a user within the application.
 * This record encapsulates essential security-related details required during
 * request processing, such as the user's ID, their granted authorities,
 * and the source of the call (gateway or internal).
 * The class is immutable, designed for thread-safety, and is used to provide
 * consistent authentication and authorization information across the system.
 *
 * @param userId The unique identifier of the authenticated user.
 * @param authorities A list of authorities granted to the user for access control.
 * @param isGatewayCall A flag indicating whether the request originated from an API Gateway.
 */
public record AuthenticationContext(
        ObjectId userId,
        List<SimpleGrantedAuthority> authorities,
        Boolean isGatewayCall
) {

    /**
     * Normalizes authorities and gateway flag for context
     */
    public AuthenticationContext {
        if (authorities == null) {
            authorities = List.of();
        }

        if (isGatewayCall == null) {
            isGatewayCall = true;
        }
    }

    /**
     * Determines if the current request is an internal call.
     * An internal call is identified as one that is not external,
     * meaning it does not originate from an API Gateway.
     *
     * @return true if the current request is an internal call; false otherwise.
     */
    public boolean isInternalCall() {
        return !isExternalCall();
    }

    /**
     * Checks if the current request is an external call.
     * An external call is identified as one originating from an API Gateway.
     *
     * @return true if the current request is an external call; false otherwise.
     */
    public boolean isExternalCall() {
        return isGatewayCall;
    }

}
