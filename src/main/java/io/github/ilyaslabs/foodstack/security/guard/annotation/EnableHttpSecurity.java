package io.github.ilyaslabs.foodstack.security.guard.annotation;

import io.github.ilyaslabs.foodstack.security.guard.HttpSecurityConfigurer;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enable HTTP security configuration in a Spring application.
 *
 * When applied to a `@Configuration` class, this annotation imports the
 * {@code HttpSecurityConfigurer} class, which sets up security filters and
 * configurations necessary for managing authentication and authorization.
 *
 * Use this annotation to activate customized HTTP security behaviors,
 * including stateless session management and custom authentication filters.
 *
 * Target: Classes annotated with `@Configuration`
 * Retention: Runtime
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(HttpSecurityConfigurer.class)
public @interface EnableHttpSecurity {
}
