package org.example.filters;

import org.example.service.CustomUserDetailsService;
import org.example.config.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
//@Component
@Order(1)
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    private boolean validateToken(String jwt) {
        return true;
    }
    private Authentication getAuthentication(String jwt) {
        return null;
    }

    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {
        String jwt = request.getHeader("Authorization");
        logger.info("hello from JWT filter");
        if (jwt == null || !jwt.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        logger.info(jwt);

        String authHeader = jwt.substring(7);
        String username = jwtUtils.extractUsername(authHeader);
        System.out.println("Extracted username: " + username);
        if (username != null && validateToken(jwt)) {
            // Set the user details in security context
            SecurityContextHolder.getContext().setAuthentication(getAuthentication(authHeader));
        }
        filterChain.doFilter(request, response);
    }
}
