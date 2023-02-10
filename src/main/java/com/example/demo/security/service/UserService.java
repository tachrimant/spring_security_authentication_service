package com.example.demo.security.service;


import com.example.demo.security.entities.Role;
import com.example.demo.security.entities.User;
import io.swagger.models.Response;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserService {

    ResponseEntity<?> addUser(User user);
    Role addNewRole(Role role);
    void addRoleToUser(String username, String rolename);
    User loadUserByUsername(String username);
    List<User> AllUsers();

}
