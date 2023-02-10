package com.example.demo.security.service.serviceImpl;

import com.example.demo.security.entities.Role;
import com.example.demo.security.entities.User;
import com.example.demo.security.repository.RoleRepository;
import com.example.demo.security.repository.UserRepository;
import com.example.demo.security.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class UserServiceImpl implements UserService {
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ResponseEntity<?> addUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return new ResponseEntity<>(
                user,
                HttpStatus.OK
        );
    }

    @Override
    public Role addNewRole(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        User user = loadUserByUsername(username);
        Role role = roleRepository.findRoleByRolename(rolename);
        user.getRoles().add(role);
        userRepository.save(user);
    }

    @Override
    public User loadUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    @Override
    public List<User> AllUsers() {
        return userRepository.findAll();
    }
}
