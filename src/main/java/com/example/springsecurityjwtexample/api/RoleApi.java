package com.example.springsecurityjwtexample.api;

import com.example.springsecurityjwtexample.domain.Response.HttpResponse;
import com.example.springsecurityjwtexample.domain.model.Role;
import com.example.springsecurityjwtexample.repository.RoleRepository;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/role")
public class RoleApi {

    private final RoleRepository roleRepository;

    public RoleApi(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @PostMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createRole(Role role){
        Role r = roleRepository.save(role);
        return new ResponseEntity<>(new HttpResponse(true, 200, "Create role success", role), HttpStatus.OK);
    }

    @DeleteMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> delete(@PathVariable Long id){
        roleRepository.deleteById(id);
        return new ResponseEntity<>(new HttpResponse(true, 200, "Delete role success", null), HttpStatus.OK);
    }

    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAll(){
        List<Role> roles = roleRepository.findAll();
        return new ResponseEntity<>(new HttpResponse(true, 200, "Get all roles", roles), HttpStatus.OK);
    }
}
