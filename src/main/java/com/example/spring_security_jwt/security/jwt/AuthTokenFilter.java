package com.example.spring_security_jwt.security.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.spring_security_jwt.security.service.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

// Punto 19 de la guía.
//
// ============================================================================
// CONVENCION DE COMENTARIOS
// Todo lo que lleve el prefijo "[IA]" lo ha escrito una IA (no es codigo tuyo)
// y explica el PORQUE de ese cambio. El resto de comentarios son tuyos.
// Para ver solo mis cambios:  grep -rn "\[IA\]" src/main/java
// ============================================================================
//
@RequiredArgsConstructor 
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        
        try {

            String jwt = parseJwt(request);

            // [IA] Este bloque entero es mio (antes solo se leia el token y se
            // tiraba el resultado). Motivo: no basta con LEER el token, hay que
            // validarlo y meter al usuario en el SecurityContextHolder, que es
            // donde Spring Security mira para saber quien es la peticion. Sin esto
            // el usuario nunca llegaba a autenticarse y cualquier peticion con
            // token era tratada como anónima.
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);

            }

        } catch (Exception e) {

            // [IA] Antes esto solo decia "// TODO: handle exception" y se comia la
            // excepcion sin registrar nada, asi que si el token fallaba no habia
            // forma de saberlo. Ahora se loguea para poder diagnosticarlo.
            LOGGER.error("No se puede autenticar la peticion: {}", e.getMessage());

        }

        // [IA] Esta linea es la que fallaba y era la causa raiz de tu problema.
        // Explicacion: un filtro de la cadena DEBE llamar a filterChain.doFilter()
        // para pasar el control al siguiente filtro. Si no lo hace, la cadena se
        // corta aqui, la peticion nunca llega al DispatcherServlet (y por tanto
        // nunca llega a tus controladores) y Tomcat responde con un 200 vacio.
        // Por eso Postman no veia nada: la peticion si salia, pero moria aqui.
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        
        String headerAuth = request.getHeader("Authorization");

        // [IA] Cambio mio: antes comparaba con "Bearer: " (con dos puntos). El
        // formato correcto del estandar es "Bearer " seguido del token, sin dos
        // puntos. Con los dos puntos, substring(7) dejaba un espacio delante del
        // token y la firma no coincidia, asi que ningun token era valido.
        // Ojo: en Postman el header se escribe exactamente "Bearer <token>".
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {

            return headerAuth.substring(7); // posición 7 de lo que devuelve headerAuth
            
        }

        return null;
    }

}
