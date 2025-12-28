package io.github.ilyaslabs.foodstack.security.guard.model;

import io.github.ilyaslabs.foodstack.security.guard.SecurityHeaders;
import org.bson.types.ObjectId;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
public record AuthenticationContext(
        ObjectId userId,
        List<SimpleGrantedAuthority> scopes
) {

    /**
     * Checks if the current request is an internal call by verifying
     * if the necessary authority is present in the scopes.
     *
     * @return true if the current request is identified as an internal call
     * (based on the presence of the `X-API-GATEWAY` authority in the scopes),
     * otherwise false.
     */
    public boolean isInternalCall() {
        return !isExternalCall();
    }

    /**
     * Determines if the current request is an external call.
     * An external call is identified by the presence of the
     * `X-API-GATEWAY` authority in the provided scopes.
     *
     * @return true if the `X-API-GATEWAY` authority is present
     * in the scopes, indicating an external call; false otherwise.
     */
    public boolean isExternalCall() {
        return scopes.contains(new SimpleGrantedAuthority(SecurityHeaders.X_API_GATEWAY.getName()));
    }

}
