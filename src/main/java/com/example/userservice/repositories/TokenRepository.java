package com.example.userservice.repositories;

import com.example.userservice.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByValueAndExpiryAtGreaterThan(String tokenValue, Date date);
}
