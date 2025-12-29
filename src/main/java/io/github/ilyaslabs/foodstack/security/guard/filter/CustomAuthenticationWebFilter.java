package io.github.ilyaslabs.foodstack.security.guard.filter;

import io.github.ilyaslabs.foodstack.security.guard.SecurityHeaders;
import io.github.ilyaslabs.foodstack.security.guard.model.AuthenticationContext;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bson.types.ObjectId;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * This filter is responsible for authenticating incoming HTTP requests by extracting user-specific
 * information from custom headers and setting the authentication context within the security context.
 * It is executed once per request.
 * The filter performs the following:
 * - Checks if the security context already contains authentication information; if present, the filter
 * chain is continued without further processing.
 * - Extracts the user ID from a custom header, {@link SecurityHeaders#X_USER_ID}, if it is present and valid.
 * - Extracts the associated security scopes from another custom header, {@link SecurityHeaders#X_SCOPES}, and converts
 * them into a collection of {@link SimpleGrantedAuthority}.
 * - Creates an {@link AuthenticationContext} object using the extracted user ID and scopes.
 * - Sets the authentication context within the {@link SecurityContextHolder}.
 * - Continues the filter chain after successfully processing the request.
 * If the required headers are not present or valid, the filter simply delegates to the next filter in the chain
 * without setting any authentication information.
 * This filter is designed to integrate seamlessly with Spring Security's authentication mechanism.
 */
public class CustomAuthenticationWebFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull FilterChain filterChain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        ObjectId userId = Optional.ofNullable(request.getHeader(SecurityHeaders.X_USER_ID.getName()))
                .filter(ObjectId::isValid)
                .map(ObjectId::new)
                .orElse(null);

        List<SimpleGrantedAuthority> scopeList = Optional.ofNullable(request.getHeader(SecurityHeaders.X_SCOPES.getName()))
                .map(scopes -> Arrays.stream(scopes.split(" "))).orElse(Stream.of(""))
                .filter(StringUtils::hasText)
                .map(SimpleGrantedAuthority::new)
                .toList();

        // if request contains X-API-GATEWAY header, consider it as a gateway call
        boolean isGatewayCall = request.getHeader(SecurityHeaders.X_API_GATEWAY.getName()) != null;

        AuthenticationContext authenticationContext = new AuthenticationContext(userId, scopeList, isGatewayCall);

        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(authenticationContext, null, scopeList));

        filterChain.doFilter(request, response);
    }
}
