package org.example.filters;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.example.controller.Controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
//@Component
@Order(2)
public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private static final Logger logger = LoggerFactory.getLogger(Controller.class);
    private final AuthenticationManager authenticationManager;
    public CustomUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setAuthenticationManager(authenticationManager);
    }
//    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

//    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        response.setHeader("Authorization", "Bearer " + "your-jwt-token");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, jakarta.servlet.FilterChain filterChain) throws io.jsonwebtoken.io.IOException, jakarta.servlet.ServletException, java.io.IOException {
        //Pre-Filter
        String username = servletRequest.getParameter("username");
        String pwd = servletRequest.getParameter("password");
        logger.info("Attempting to authenticate user: " + username);  // Log the username
        UsernamePasswordAuthenticationToken authtoken = new UsernamePasswordAuthenticationToken(username, pwd);
        try{
            authenticationManager.authenticate(authtoken);
            filterChain.doFilter(servletRequest, servletResponse);
        }catch(Exception e){
            logger.info("Couldn't authenticate");
        }
}}