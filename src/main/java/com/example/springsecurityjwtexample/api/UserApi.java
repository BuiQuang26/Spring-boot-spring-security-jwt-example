package com.example.springsecurityjwtexample.api;

import com.example.springsecurityjwtexample.domain.Response.HttpResponse;
import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.UserRepository;
import com.example.springsecurityjwtexample.service.UserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@SecurityRequirement(name = "bearerAuth")
@RequestMapping("/api/user")
public class UserApi {

    private final UserService userService;

    public UserApi(UserRepository userRepository, UserService userService) {
        this.userService = userService;
    }

    @PostMapping(value = "/login")
    public void login(@RequestBody User user){}

    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> userRegister(@RequestBody @Valid User user){
        User u = userService.register(user);
        return new ResponseEntity<>(new HttpResponse(true, 200, "Register success", user), HttpStatus.OK);
    }

    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUser(){
        List<User> users = userService.getAll();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }
}
