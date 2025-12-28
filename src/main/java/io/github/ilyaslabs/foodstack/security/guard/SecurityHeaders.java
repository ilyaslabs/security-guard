package io.github.ilyaslabs.foodstack.security.guard;

/**
 * Security Headers that will be used for internal security purposes.
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
public enum SecurityHeaders {

    /**
     * Represents that the request is coming from API Gateway.
     */
    X_API_GATEWAY("X-API-GATEWAY"),

    /**
     * Represents the scopes of the user.
     */
    X_SCOPES("X-SCOPES"),

    /**
     * Represents the user ID.
     */
    X_USER_ID("X-USER-ID");

    private final String headerName;

    /**
     * Constructor.
     * @param headerName String
     */
    SecurityHeaders(String headerName) {
        this.headerName = headerName;
    }

    /**
     * Returns the header name.
     * @return String
     */
    public String getName() {
        return headerName;
    }
}
