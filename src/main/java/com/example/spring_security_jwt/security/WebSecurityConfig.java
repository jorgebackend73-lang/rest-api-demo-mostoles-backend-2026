package com.example.spring_security_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
    // Otro Bean para
    @Bean 
    DaoAuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
    
        authProvider.setPasswordEncoder(PasswordEncoder());

        return authProvider;
    }

    @Bean 
    PasswordEncoder PasswordEncoder() {
    
        return new BCryptPasswordEncoder();

    }

    @Bean 
    AuthenticationManager authenticationManager (AuthenticationConfiguration authConfig) {

        return  authConfig.getAuthenticationManager();
    }

    // El bean siguiente es el que hay que saber personalizar para adaptarlo a nuestro proyecto
    // Lo demás es boilerplate o código repetitivo

    @Bean 
    SecurityFilterChain filterChain(HttpSecurity http) {

        // CSRF es una proteccion para webs que usan cookies de sesion.
		// Nuestra API usa tokens JWT (no cookies), asi que la desactivamos
        http.csrf(csrf -> csrf.disable()) // desbilitamos esta protección
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizeHandle))
            // para que no se quede nada stateless
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // lugar de la página web donde se puede acceder sin seguridad, para dar de alta a un usuario
            // y/o autenticarse. Pero a partir de aquí tienes que estar autenticado y securizado.
            // [IA] Cambio mio: he añadido "/error" a la lista de permitAll().
            // Motivo: cuando un controlador falla (400, 403, 404...), Spring
            // reenvia la peticion a /error para que pinte el error. Con
            // anyRequest().authenticated() ese /error volvia a pasar por esta
            // cadena de filtros, y como AuthTokenFilter es un OncePerRequestFilter
            // (que por defecto NO se ejecuta en los reenvios ERROR) no releia el
            // token: el SecurityContext llegaba vacío y la respuesta terminaba
            // siendo 401 SIEMPRE. Efecto: todos los errores reales (400, 403, 404)
            // llegaban a Postman camuflados como 401, y por eso costs
            // imposible depurar. Autorizar /error deja que cada error conserve
            // su codigo verdadero. Es el patron habitual en Spring Boot + Security.
            .authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**", "/error").permitAll()
            // a partir de aquí 
            .anyRequest().authenticated());
            
            http.authenticationProvider(authenticationProvider());

            http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);    

            return http.build();

    }

}
