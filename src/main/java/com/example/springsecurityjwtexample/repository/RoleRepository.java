package com.example.springsecurityjwtexample.repository;

import com.example.springsecurityjwtexample.domain.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
