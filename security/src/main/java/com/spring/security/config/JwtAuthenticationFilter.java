package com.spring.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{


    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; //implemented service from org.springframework.security.core.userdetails.UserDetailsService
                                                         //should make bean for it in configApp
    @Override
    protected void doFilterInternal(@NonNull   HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader=request.getHeader("Authorization" );
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){ //7ch
            filterChain.doFilter(request,response); // pass the req and response to the next filter
            return;
        }


        jwt=authHeader.substring(7);

        userEmail=  jwtService.extractUsername(jwt);//extract user email

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ //mat3mlho4 auth before

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

        }

    }
}
