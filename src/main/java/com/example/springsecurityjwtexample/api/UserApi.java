package com.example.springsecurityjwtexample.api;

import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.UserRepository;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@SecurityRequirement(name = "bearerAuth")
@RequestMapping("/api/user")
public class UserApi {

    @Autowired
    UserRepository userRepository;

    @PostMapping(value = "/login")
    public void login(@RequestBody User user){}

    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> userRegister(@RequestBody User user){
        return null;
        //todo
    }

    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllUser(){
        return new ResponseEntity<>(userRepository.findAll(), HttpStatus.OK);
    }
}
