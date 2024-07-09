package com.example.userservice.controllers;

import com.example.userservice.dtos.UserLoginRequestDto;
import com.example.userservice.dtos.UserSignUpRequestDto;
import com.example.userservice.dtos.UserResponseDto;
import com.example.userservice.models.User;
import com.example.userservice.models.Token;
import com.example.userservice.services.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    private UserService userService;
    public UserController(UserService userService){
        this.userService = userService;
    }
    @PostMapping("/signup")
    public UserResponseDto signUp(@RequestBody UserSignUpRequestDto userSignUpRequestDto){
        User user = userService.signUp(userSignUpRequestDto.getName(),
                            userSignUpRequestDto.getEmail(),
                            userSignUpRequestDto.getPassword());

        return UserResponseDto.from(user);
    }
    @GetMapping("/login")
    public Token login(@RequestBody UserLoginRequestDto userLoginRequestDto){
        return userService.login(userLoginRequestDto.getEmail(), userLoginRequestDto.getPassword());
    }

    @PostMapping("/validate/{token}")
    public UserResponseDto validateToken(@PathVariable String token){
        User user;
        try{
            user = userService.validateToken(token);
        }catch (Exception e){
            return null;
        }
        return UserResponseDto.from(user);
    }
}
