package com.seungwook.jwt.repository;

import com.seungwook.jwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUuid(String uuid);
    Optional<User> findBySearchableHash(String searchableHash);
}
