package org.example.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {
    private static final Logger logger = LoggerFactory.getLogger(Controller.class);

    @PostMapping("/tst")
    public ResponseEntity<String> tst(){
        System.out.println("halls");
        logger.info("Request received at /tst");
        return ResponseEntity.ok("Hello from test");
    }

    @PostMapping("/login")
    public ResponseEntity<String> createAuthToken() {
        logger.info("Request received at /login");
        return new ResponseEntity<>("nice one", HttpStatusCode.valueOf(202));
    }
//    @Bean
//    FilterRegistrationBean<CustomUsernamePasswordAuthenticationFilter> filterFilterRegistrationBean(){
//        FilterRegistrationBean<CustomUsernamePasswordAuthenticationFilter> filterFilterRegistration = new FilterRegistrationBean<>();
//        filterFilterRegistration.setFilter(new CustomUsernamePasswordAuthenticationFilter(new AuthenticationManager() {
//            @Override
//            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//                return null;
//            }
//        }));
//        filterFilterRegistration.addUrlPatterns("/login");
//        return filterFilterRegistration;
//    }
//    @Bean
//    public FilterRegistrationBean<JwtFilter> jwtFilterRegistration() {
//        FilterRegistrationBean<JwtFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(new JwtFilter());
//        registrationBean.addUrlPatterns("/login");
//        return registrationBean;
//    }


}
