package com.example.spring_security_jwt.controller;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.spring_security_jwt.model.ERole;
import com.example.spring_security_jwt.model.Role;
import com.example.spring_security_jwt.model.User;
import com.example.spring_security_jwt.payload.request.LogginRequest;
import com.example.spring_security_jwt.payload.request.SignupRequest;
import com.example.spring_security_jwt.payload.response.JwtResponse;
import com.example.spring_security_jwt.payload.response.MessageResponse;
import com.example.spring_security_jwt.repository.RoleRepository;
import com.example.spring_security_jwt.repository.UserRepository;
import com.example.spring_security_jwt.security.jwt.JwtUtils;
import com.example.spring_security_jwt.security.service.UserDetailsImpl;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController // para recibir peticiones
@RequestMapping("/api/auth") // por donde respondemos las peticiones no securizadas
@RequiredArgsConstructor // para suministrar por constructor los argumentos
public class AuthController {

    // Dependencias para los metodos que vamos a implementar

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder encoder;

    private final JwtUtils jwtUtils;

    // Logger

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    // Método para usuario hacer signup

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest,
            BindingResult validationResults) {

        // si existe el nombre de usuario hay que confirmarlo y decirlo.
        if (userRepository.existsByUsername(signupRequest.getUsername())) {

            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Username is already taken!!!"));

        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {

            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Email is already in use!!!"));
        }

        User user = User.builder()
                .username(signupRequest.getUsername())
                .email(signupRequest.getEmail())
                .password(encoder.encode(signupRequest.getPassword()))
                .build();

        // Creamos los roles
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {

            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found!!!"));

            roles.add(userRole);

        } else {
            strRoles.forEach(role -> {

                if (role == "admin") {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not foun!!!"));

                    roles.add(adminRole);

                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role not found!!!"));
                    roles.add(userRole);

                }

                // strRoles.forEach(role -> {

                // switch (role) {
                // case "admin":
                // Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                // .orElseThrow(() -> new RuntimeException("Error: Role is not foun!!!"));

                // roles.add(adminRole);

                // break;

                // default:
                // Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                // .orElseThrow(() -> new RuntimeException("Error: Role not found!!!"));

                // roles.add(userRole);

                // break;

                // }

            });

        }

        user.setRoles(roles);

        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered succesfully!!!"));

    }

    // Metodo que permite logearse a un usuario que se ha registrado previamente
    @PostMapping("/signin")
    // ResponseEntity de cualquier cosa <?>
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LogginRequest logginRequest, BindingResult result) {

        // TODO. Validar el JSON recibido en el cuerpo de la peticion.
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(logginRequest.getUsername(),
                        logginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);

        // Creamos el objeto userDetails de tipo UserDetailsImpl, al darle valor hay que
        // castearlo para que el objeto
        // authentication del que cogemos la auth principal se amolde al tipo de objeto
        // UserDetailImpl que vamos a usar
        // más abajo.
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Lista de strings con una variable roles que toma el valor del objeto
        // userDetails del cual toma sus Autorizaciones.
        // pasamos los conjuntos de autorizaciones o roles a traves de un flujo o
        // stream, que luego mapeamos y recogemos
        // con collect en en una lista.
        Set<String> roles = userDetails.getAuthorities()
                .stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toSet());

        // Mostrar por consola los roles del usuario que recogimos en el paso anterior
        LOGGER.info("Roles del usuario: {}" + roles);

        return ResponseEntity.ok(new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));

    }

}
