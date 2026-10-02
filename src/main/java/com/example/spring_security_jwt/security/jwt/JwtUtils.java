package com.example.spring_security_jwt.security.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.spring_security_jwt.security.service.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component 
public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @Value ("${demo.app.jwtSecret}")
    private String jwtSecret;

    @Value ("${demo.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {

        // Casteo y todo
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        // [IA] Cambio mio (esto es lo mas importante de este metodo). Antes se
        // escribia "Jwts.builder()....compact();" SIN(return, y en la linea
        // siguiente habia un "return null". Es decir: se construia el token y
        // acto seguido se tiraba a la basura. jjwt NO muta el builder: compact()
        // DEVUELVE el String del token, y ese valor hay que devolver.
        // Sin esto, /signin contestaba 200 pero con "token": null.
        //
        // Practica: cuando un metodo "fabrica" algo (un token, un id, un objeto),
        // casi siempre hay un return con el valor que produce la cadena. Si
        // compila y devuelve null, casi siempre se ha olvidado devolverlo.
        //
        // Creamos token. Partes Token: cabecera, key, claims(lo o quien dices que eres).
        return Jwts.builder()
            // claims:
            .subject(userPrincipal.getUsername())
            .issuedAt(new Date())
            .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(key())
            .compact();
    }

    // método para crear la key de java security
    private Key key() {

        // Aquí usamos el secreto con la clase que implementa los metodos de la interface
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        }

        // método para extraer el nombre de usuario del token
        public String getUserNameFromJwtToken(String token) {

            return Jwts.parser().verifyWith((SecretKey) key()).build()
                // Comprobamos claims son correctos. Los sacamos del payload del token
                .parseSignedClaims(token).getPayload().getSubject();
        }

        // Autenticación
        public boolean validateJwtToken(String authToken) {

            try {
                Jwts.parser().verifyWith((SecretKey) key()).build().parse(authToken);

                return true;
            } catch (MalformedJwtException e) {

                LOGGER.error("Invalid JWT token: {} ", e.getMessage());

            } catch (ExpiredJwtException e) {

                LOGGER.error("JWT token is expired: {} ", e.getMessage());

            } catch (UnsupportedJwtException e) {

                LOGGER.error("Unsupported JWT token: {} ", e.getMessage());

            } catch (IllegalArgumentException e) {

                LOGGER.error("JWT claims string is empty: {} ", e.getMessage());

            }

            return false;
        }

    

}
