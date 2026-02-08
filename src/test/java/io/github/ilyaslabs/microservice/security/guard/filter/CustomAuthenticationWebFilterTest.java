package io.github.ilyaslabs.microservice.security.guard.filter;

import io.github.ilyaslabs.microservice.security.guard.AuthenticationContextProvider;
import io.github.ilyaslabs.microservice.security.guard.HttpSecurityTestApplication;
import io.github.ilyaslabs.microservice.security.guard.SecurityHeaders;
import io.github.ilyaslabs.microservice.security.guard.model.AuthenticationContext;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@SpringBootTest(classes = {HttpSecurityTestApplication.class, CustomAuthenticationWebFilterTest.Endpoint.class})
@AutoConfigureMockMvc
class CustomAuthenticationWebFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @RestController
    @RequestMapping("/api/v1")
    public static class Endpoint {

        public static AuthenticationContext authenticationContext;

        private final AuthenticationContextProvider authenticationContextProvider;

        public Endpoint(AuthenticationContextProvider authenticationContextProvider) {
            this.authenticationContextProvider = authenticationContextProvider;
        }

        @GetMapping("/context")
        public String context() {
            authenticationContext = authenticationContextProvider.current();
            return "OK";
        }

        @PreAuthorize("hasAuthority('admin')")
        @GetMapping("/admin")
        public String admin() {
            return "OK";
        }
    }

    @BeforeEach
    public void setup() {
        Endpoint.authenticationContext = null;
    }

    /**
     * Test authenticate context is set correctly.
     */
    @Test
    void testAuthenticateContextIsSetCorrectly() throws Exception {
        ObjectId id = new ObjectId();
        mockMvc.perform(
                        get("/api/v1/context")
                                .header(SecurityHeaders.X_USER_ID.getName(), id.toString())
                                .header(SecurityHeaders.X_SCOPES.getName(), "read write")
                )
                .andExpect(status().isOk());

        assertThat(Endpoint.authenticationContext).isNotNull();
        assertThat(Endpoint.authenticationContext.authorities()).containsAll(
                Arrays.asList(new SimpleGrantedAuthority("read"), new SimpleGrantedAuthority("write")));
        assertThat(Endpoint.authenticationContext.userId()).isEqualTo(id);
        assertThat(Endpoint.authenticationContext.isGatewayCall()).isFalse();
    }

    /**
     * Test scope security, prevent if scope matches.
     */
    @Test
    void testScopeSecurity() throws Exception {
        mockMvc.perform(get("/api/v1/admin"))
                .andExpect(status().isForbidden());
    }

    /**
     * Test scope security, allow if the scope matches.
     */
    @Test
    void testScopeSecurityAllow() throws Exception {
        mockMvc.perform(get("/api/v1/admin")
                        .header(SecurityHeaders.X_SCOPES.getName(), "admin"))
                .andExpect(status().isOk());
    }

    @Test
    void testGatewayCall() throws Exception {
        mockMvc.perform(get("/api/v1/context")
                        .header(SecurityHeaders.X_API_GATEWAY.getName(), "true"))
                .andExpect(status().isOk());

        assertThat(Endpoint.authenticationContext.isGatewayCall()).isTrue();
    }

}