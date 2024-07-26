package com.spring.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.http.WebSocket;

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

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { //mat3mlho4 auth before

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //get user

           if(jwtService.isTokenValid(jwt ,userDetails)) { //check token valid

               UsernamePasswordAuthenticationToken authToken // make obj to get user & getAuthorities
                       = new UsernamePasswordAuthenticationToken
                       (userDetails,
                               null,
                               userDetails.getAuthorities()
                       );

               authToken // enforce auth obj with details of our request
                       .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

               //Update the SecurityContextHolder //make this user (obj) auth done to not auth after this
               SecurityContextHolder.getContext().setAuthentication(authToken);

           }
        }
        filterChain.doFilter(request,response);
    }
}
/*
Steps:
Check if the email is provided and no authentication is present.
Load user details using the email.
Validate the token with the user details.
Create an authentication token with user details.
Set additional request details.
Update the security context with the new authentication token
 */