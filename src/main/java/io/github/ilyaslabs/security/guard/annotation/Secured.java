package io.github.ilyaslabs.security.guard.annotation;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Secured mean endpoint can only be accessed between microservices and no direct access from outside.
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@secureCallEvaluator.isAllowed(authentication)")
public @interface Secured {
}
