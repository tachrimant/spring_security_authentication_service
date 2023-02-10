package com.example.demo.security.rest;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.security.entities.Role;
import com.example.demo.security.entities.User;
import com.example.demo.security.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.example.demo.security.constant.JWTUtil.*;
@RestController
@RequestMapping("/users")
public class UserRest {


    private UserService userService;

    public UserRest(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/addUser")
    public ResponseEntity<?> addUser(@RequestBody User user) {
        return userService.addUser(user);
    }

    @PostMapping("/addRole")
    public Role addNewRole(@RequestBody Role role) {
        return userService.addNewRole(role);
    }

    @PostMapping("addRole-to-User")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        userService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRolename());
    }

    @GetMapping(path = "/username")
    public User loadUserByUsername(Principal principal) {
        return userService.loadUserByUsername(principal.getName());
    }

    @GetMapping("/")
    public List<User> AllUsers() {
        return userService.AllUsers();
    }


    @GetMapping("/isAdmin")
    @PostAuthorize("hasAuthority('ADMIN')")
    public String isAdmin(){
        return "current logged user has authority ADMIN";
    }

    @GetMapping("/isUser")
    @PostAuthorize("hasAuthority('USER')")
    public String isUser(){
        return "current logged user has authority USER";
    }

    @GetMapping("/refreshToken")
    public void refrechToken(HttpServletRequest request, HttpServletResponse response) throws IOException{

        String authToken = request.getHeader(AUTH_HEADER);

        if (authToken != null && authToken.startsWith(PREFIX)){
            try {
                String jwt = authToken.substring(PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                User user = userService.loadUserByUsername(username);
                String newAccessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() +EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getRoles().stream().map(r-> r.getRolename()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("access_token",newAccessToken);
                idToken.put("refresh_token",jwt);
                response.setContentType("application/json");

                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            } catch (Exception e) {
                throw  new RuntimeException("Something went wrong While creating Access_Token!");
            }

        }else {
            throw new RuntimeException("Refrech_Token required !!");
        }
    }
}
