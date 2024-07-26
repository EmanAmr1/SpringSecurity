package com.spring.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


   private final JwtAuthenticationFilter jwtAuthenticationFilter;
   private final AuthenticationProvider authenticationProvider; //make bean for this

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


                http
            .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);





        return http.build();


    }


    /*
    -http: Provides a fluent API for configuring HTTP security
    -Disables CSRF (Cross-Site Request Forgery) protection , CSRF protection is typically disabled when using stateless authentication like JWT
    -authorizeHttpRequests(authz -> authz: Configures HTTP request authorization. It sets up rules for which requests should be permitted or require authentication.
    -Configures session management to be stateless. This means that the server will not create or maintain any session state between requests, which is suitable for stateless authentication methods like JWT
    -Sets the custom AuthenticationProvider for handling authentication. This allows for custom authentication logic, such as validating JWTs
    -Adds a custom filter (jwtAuthFilter) before the default UsernamePasswordAuthenticationFilter. This filter will be used to process JWT authentication before the username and password authentication filter.
    -return http.build(): Builds and returns the SecurityFilterChain instance. This finalizes the security configuration and applies it to the application context
     */

}
