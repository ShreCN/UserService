package com.example.userservice.services;

import com.example.userservice.exceptions.UserNotFoundException;
import com.example.userservice.models.User;
import com.example.userservice.models.Token;
import com.example.userservice.repositories.TokenRepository;
import com.example.userservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenRepository tokenRepository;

    public UserService(UserRepository userRepository,
                       BCryptPasswordEncoder bCryptPasswordEncoder,
                       TokenRepository tokenRepository){
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenRepository = tokenRepository;
    }

    public User signUp(String name, String email, String password) {
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));
        return userRepository.save(user);
    }

    public Token login(String email, String password) {

//        1. Verify user exists
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isEmpty()){
            throw new UserNotFoundException("User not found for email "+email);
        }
//        2. Verify the Password
        if(!bCryptPasswordEncoder.matches(password, user.get().getHashedPassword())){
            throw new UserNotFoundException("Invalid credentials");
        }
//        3. Generate the Token
        Token token = geneateToken(user.get());
        return token;
    }

    private Token geneateToken(User user){
        Token token = new Token();
        token.setUser(user);
        token.setValue(RandomStringUtils.randomAlphabetic(10));

        LocalDate expiryLocalDate = LocalDate.now().plusMonths(1);
        Date expiryDate  = Date.from(expiryLocalDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
        token.setExpiryAt(expiryDate);
        tokenRepository.save(token);
        return token;
    }

    public User validateToken(String tokenValue) {
        Optional<Token> token = tokenRepository.findByValueAndExpiryAtGreaterThan(tokenValue, new Date());
        if(token.isEmpty()) {
            throw new RuntimeException("InvalidToken");
        }

        return token.get().getUser();
    }
}
