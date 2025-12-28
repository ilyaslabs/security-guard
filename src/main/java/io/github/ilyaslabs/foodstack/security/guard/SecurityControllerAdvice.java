package io.github.ilyaslabs.foodstack.security.guard;

import io.github.ilyaslabs.microservice.exception.HttpResponseException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
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
