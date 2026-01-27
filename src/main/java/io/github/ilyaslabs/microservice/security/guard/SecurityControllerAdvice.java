package io.github.ilyaslabs.microservice.security.guard;

import io.github.ilyaslabs.microservice.exception.HttpResponseException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * A controller advice that provides exception handling for security-related exceptions.
 * This class centralizes the handling of exceptions, such as `AccessDeniedException`, and provides custom responses
 * to enhance security and user experience.
 * Key Features:
 * - Logs security exceptions with a warning level to assist with debugging and monitoring.
 * - Customizes HTTP responses for specific security-related exceptions, such as returning a 403 Forbidden status
 * for access denial scenarios.
 */
@ControllerAdvice
@Slf4j
public class SecurityControllerAdvice {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponseException.ResponseBody> handleAccessDeniedException(AccessDeniedException exception) {
        log.warn("Access Denied: {}", exception.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(HttpResponseException.ofForbidden("Access Denied")
                .toResponseBody());
    }
}
