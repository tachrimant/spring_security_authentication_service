package com.example.demo;

import com.example.demo.security.entities.Role;
import com.example.demo.security.entities.User;
import com.example.demo.security.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)

public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(UserService userService) {
        return args -> {
            userService.addNewRole(new Role(null, "USER"));
            userService.addNewRole(new Role(null, "ADMIN"));
            userService.addUser(new User(null, "user1", "ahmeddahbiok@gmail.com","+212685749632",1258963, new ArrayList<>()));
            userService.addUser(new User(null, "ahmeddahbi", "dahbiahmed1999@gmail.com","+212682450274", 1578963, new ArrayList<>()));
            userService.addRoleToUser("user1", "USER");
            userService.addRoleToUser("ahmeddahbi", "ADMIN");
        };
    }
}
