package io.github.ilyaslabs.microservice.security.guard;

import io.github.ilyaslabs.microservice.security.guard.filter.CustomAuthenticationWebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures the security settings for the application, integrating Spring Security components such as
 * custom authentication filters, security configurations, and filter chains.
 * Responsibilities:
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class HttpSecurityConfigurer {

    /**
     * Provides a custom authentication filter for processing HTTP requests and extracting
     * user-specific authentication details using custom headers.
     *
     * @return an instance of {@link CustomAuthenticationWebFilter} configured to integrate with
     *         Spring Security's an authentication mechanism.
     */
    @Bean
    CustomAuthenticationWebFilter customAuthenticationWebFilter() {
        return new CustomAuthenticationWebFilter();
    }

    /**
     * Creates and provides a {@link SecurityConfig} bean that integrates with the application's
     * custom authentication filter.
     *
     * @param customAuthenticationWebFilter an instance of {@link CustomAuthenticationWebFilter}
     *                                       used to handle user authentication details in incoming HTTP requests.
     * @return a configured {@link SecurityConfig} object.
     */
    @Bean
    public SecurityConfig securityConfig(CustomAuthenticationWebFilter customAuthenticationWebFilter) {
        return new SecurityConfig(customAuthenticationWebFilter);
    }

    /**
     * Configures and provides a security filter chain for the application.
     *
     * @param securityConfig the {@link SecurityConfig} object used for configuring security settings.
     * @param httpSecurity the {@link HttpSecurity} object to be configured for application security.
     * @return the configured {@link SecurityFilterChain} instance.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(SecurityConfig securityConfig, HttpSecurity httpSecurity) {
        return securityConfig.httpSecurity(httpSecurity);
    }

    /**
     * Provides a {@link SecureCallEvaluator} bean used to evaluate whether a particular call
     * or request is authorized based on the associated authentication context.
     *
     * @return an instance of {@link SecureCallEvaluator} for validating security-related conditions.
     */
    @Bean
    public SecureCallEvaluator secureCallEvaluator() {
        return new SecureCallEvaluator();
    }

    /**
     * Provides a {@link SecurityControllerAdvice} bean that handles global exception handling for security-related
     * issues, such as access denied exceptions, and customizes the response accordingly.
     *
     * @return an instance of {@link SecurityControllerAdvice} configured to intercept and handle specific exceptions.
     */
    @Bean
    public SecurityControllerAdvice securityControllerAdvice() {
        return new SecurityControllerAdvice();
    }

    /**
     * Provides a {@link UserDetailsService} bean that is configured to throw a
     * {@link UsernameNotFoundException} for any username lookup. This implementation
     * effectively disables user details retrieval.
     *
     * @return an instance of {@link UserDetailsService} that always throws a
     *         {@link UsernameNotFoundException} with a message indicating that the service is disabled.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return _ -> {
            throw new UsernameNotFoundException("UserDetailsService disabled");
        };
    }

}
