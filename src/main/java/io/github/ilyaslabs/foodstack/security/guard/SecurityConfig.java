package io.github.ilyaslabs.foodstack.security.guard;

import io.github.ilyaslabs.foodstack.security.guard.filter.CustomAuthenticationWebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationWebFilter customAuthenticationWebFilter;

    /**
     * Creates a basic filter chain required for microservice security.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured HttpSecurity object
     * @throws Exception if an error occurs during configuration
     */
    public SecurityFilterChain httpSecurity(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                //make session less
                .sessionManagement(customizer ->
                        customizer
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .cors(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(customAuthenticationWebFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(customizer ->
                        customizer
                                .authenticationEntryPoint(this::unauthorizedResponse)
                );

        return http.build();
    }

    /**
     * Handles an unauthorized response by sending an HTTP 401 status code.
     *
     * @param httpServletRequest the HTTP servlet request triggering the unauthorized response
     * @param response           the HTTP servlet response to send the error to
     * @param e                  the authentication exception that caused the unauthorized response
     * @throws IOException if an input or output error occurs while sending the error response
     */
    private void unauthorizedResponse(HttpServletRequest httpServletRequest, HttpServletResponse response, AuthenticationException e) throws IOException {
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

}
