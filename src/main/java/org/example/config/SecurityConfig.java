package org.example.config;

//import org.example.service.user.JwtFilter;
import org.example.filters.CustomUsernamePasswordAuthenticationFilter;
import org.example.filters.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.example.service.CustomUsernamePasswordAuthenticationFilter;

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
            CustomUsernamePasswordAuthenticationFilter customAuthFilter = new CustomUsernamePasswordAuthenticationFilter(authenticationManager);
            JwtFilter jwtFilter = new JwtFilter();
            http
                    .csrf(AbstractHttpConfigurer::disable)  // Disable CSRF with the new method
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers(  "/login","/tst").permitAll()
                            .anyRequest().authenticated()
                    );

            // Add custom username-password filter and JWT filter
            http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
            http.addFilter(customAuthFilter);

            return http.build();
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
            return authenticationConfiguration.getAuthenticationManager();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

//        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring()
                    .requestMatchers("/tst");
        }
    }