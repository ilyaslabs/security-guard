package io.github.ilyaslabs.foodstack.security.guard;

import io.github.ilyaslabs.foodstack.security.guard.filter.CustomAuthenticationWebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class HttpSecurityConfigurer {

    @Bean
    CustomAuthenticationWebFilter customAuthenticationWebFilter() {
        return new CustomAuthenticationWebFilter();
    }

    @Bean
    public SecurityConfig securityConfig(CustomAuthenticationWebFilter customAuthenticationWebFilter) {
        return new SecurityConfig(customAuthenticationWebFilter);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(SecurityConfig securityConfig, HttpSecurity httpSecurity) throws Exception {
        return securityConfig.httpSecurity(httpSecurity);
    }

    @Bean
    public SecureCallEvaluator secureCallEvaluator() {
        return new SecureCallEvaluator();
    }

    @Bean
    public SecurityControllerAdvice securityControllerAdvice() {
        return new SecurityControllerAdvice();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            throw new UsernameNotFoundException("UserDetailsService disabled");
        };
    }

}
