package com.example.spring_security_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import com.example.spring_security_jwt.security.jwt.AuthEntryPointJwt;
import com.example.spring_security_jwt.security.jwt.AuthTokenFilter;
import com.example.spring_security_jwt.security.jwt.JwtUtils;
import com.example.spring_security_jwt.security.service.UserDetailsServiceImpl;

import lombok.RequiredArgsConstructor;

@Configuration 
// La anotación de abajo es para ahorrar mucho trabajo a la hora de permitir métodos dependiendo del rol autenticado
// y permite: secureEnable = true, jsr250Enable = true y prePostEnabled = true.
// Así se pueden securizar directamente los métodos de los controladores, donde se delegan
// las peticiones a los endpoints.
@EnableMethodSecurity
@RequiredArgsConstructor 
public class WebSecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;

    private final AuthEntryPointJwt unauthorizeHandle;

    private final JwtUtils jwtUtils;
   
    @Bean 
    AuthTokenFilter authenticationJwtTokenFilter() {

        return new AuthTokenFilter(jwtUtils, userDetailsService);


    }

}
