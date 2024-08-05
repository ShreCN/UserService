package com.example.userservice.services;

import com.example.userservice.configurations.KafkaProducerConfig;
import com.example.userservice.dtos.SendMessageDto;
import com.example.userservice.dtos.UserResponseDto;
import com.example.userservice.exceptions.UserNotFoundException;
import com.example.userservice.models.User;
import com.example.userservice.models.Token;
import com.example.userservice.repositories.TokenRepository;
import com.example.userservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Service
public class UserService {
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenRepository tokenRepository;
    private KafkaTemplate<String, String> kafkaTemplate;
    private ObjectMapper objectMapper;

    public UserService(UserRepository userRepository,
                       BCryptPasswordEncoder bCryptPasswordEncoder,
                       TokenRepository tokenRepository,
                       KafkaTemplate<String, String> kafkaTemplate,
                       ObjectMapper objectMapper){
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenRepository = tokenRepository;
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
    }

    public User signUp(String name, String email, String password) throws ExecutionException, InterruptedException {
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));

        User savedUser = userRepository.save(user);

        // send welcome mail for successful sign up
        // Kafka Publish sendMail Event
        SendMessageDto messageDto = new SendMessageDto();
        messageDto.setTo(savedUser.getEmail());
        messageDto.setFrom("shre74024@gmail.com");
        messageDto.setBody("Hope you have great Shopping experience");
        messageDto.setSubject("Welcome !!!!!");
        CompletableFuture<SendResult<String, String>> result = null;
        try {
             result = kafkaTemplate.send(
                    "sendEmail",
                    objectMapper.writeValueAsString(messageDto));
        }catch (Exception e){
            System.out.println("Object Mapper Exception occurred");
        }
        System.out.println(result.get());
        return savedUser;
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
