package io.github.ilyaslabs.foodstack.security.guard;

import io.github.ilyaslabs.foodstack.security.guard.annotation.Secured;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@SpringBootTest(classes = {HttpSecurityTestApplication.class, TestSecuredAnnotation.SecuredEndpoint.class})
@AutoConfigureMockMvc
class TestSecuredAnnotation {

    @Autowired
    private MockMvc mockMvc;

    @RestController
    public static class SecuredEndpoint {

        @Secured
        @GetMapping("/secured")
        public String securedMethod() {
            return "Secured response";
        }

        @GetMapping("/insecured")
        public String inSucreMethod() {
            return "Insecure response";
        }
    }

    /**
     * Tests whether secured endpoints are not accessible from outside without appropriate authorization.
     * Specifically, it simulates an external request to the secured endpoint with headers mimicking
     * an unauthorized external call and verifies that the response status is HTTP 403 Forbidden.
     * The test ensures that @Secured endpoints, by design, protect sensitive services from being accessed
     * externally, enforcing the authorization constraints defined in the system.
     *
     * @throws Exception if any unexpected error occurs during the request simulation or validation
     */
    @Test
    void testIfSecuredEndpointsAreNotAccessibleFromOutside() throws Exception {

        mockMvc.perform(get("/secured")
                        .header(SecurityHeaders.X_API_GATEWAY.getName(), "true")
                )
                .andExpect(status().isForbidden());

    }

    /**
     * Tests whether non-secured endpoints are accessible from outside without requiring any
     * specific authorization or security headers.
     * <p>
     * Specifically, the test simulates an external request to an unsecured endpoint and
     * verifies that the response status is HTTP 200 OK, confirming that the endpoint is
     * publicly accessible as intended.
     * <p>
     * The test ensures that endpoints without the @Secured annotation allow unrestricted
     * external access, per the expected system behavior.
     *
     * @throws Exception if any unexpected error occurs during the request simulation or validation
     */
    @Test
    void testIfInsecureEndpointsAreAccessibleFromOutside() throws Exception {
        mockMvc.perform(get("/insecured"))
                .andExpect(status().isOk());
    }
}
