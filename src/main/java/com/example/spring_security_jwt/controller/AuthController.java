package com.example.spring_security_jwt.controller;

import java.util.HashSet;
import java.util.List;
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

        // [IA] Bloque mio. Explicacion de por que hace falta: cuando pones @Valid
        // delante de un @RequestBody y ADEMAS un BindingResult a continuacion,
        // Spring NO lanza excepcion si el JSON es invalido. Se limita a rellenar
        // validationResults con la lista de errores y sigue metiendo el metodo.
        // Es decir: el metodo se ejecuta SIEMPRE, y si tu no miras
        // validationResults, los datos rubbish llegan intactos hasta el save().
        // Con el ejemplo {"username":"ab","email":"bad","password":"1"} se intentaba
        // guardar en MySQL y reventaba con DataIntegrityViolationException, o sea
        // un HTTP 500 feo, en vez de un 400 elegante con el motivo real.
        //
        // Regla: si escribes @Valid, tienes que consultar el BindingResult.
        if (validationResults.hasErrors()) {

            List<String> errores = validationResults.getFieldErrors()
                    .stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.toList());

            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error en los datos recibidos: " + errores));
        }

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

                // [IA] Cambio mio: antes era "if (role == "admin")". Explicacion:
                // el operador == con dos String NO compara el texto, compara si
                // son el MISMO objeto en memoria. Solo es true para literales
                // "administrados" por la JVM. Los String que llegan aqui vienen
                // deserializados del JSON, y esos no estan administrados, asi que
                // == era false SIEMPRE y todos los usuarios se registraban como USER
                // (da igual lo que mandases en "role"). Con equals() se compara
                // el contenido y el rol admin ya se concede bien.
                if ("admin".equals(role)) {
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

        // [IA] Este bloque sustituye a tu "// TODO. Validar el JSON recibido...".
        // Funciona igual que el de signup y por el mismo motivo: el @Valid de la
        // firma no lanza nada, solo acumula los fallos en "result". Si no se mira,
        // un cuerpo vacio ({}), o sin password, llega con null hasta el
        // authenticationManager y la peticion acaba en un 500 sin explicar nada.
        if (result.hasErrors()) {

            List<String> errores = result.getFieldErrors()
                    .stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.toList());

            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error en los datos recibidos: " + errores));
        }

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
