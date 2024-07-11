package com.example.userservice.security.models;

import com.example.userservice.models.Role;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
@JsonDeserialize
@Getter
@Setter
@NoArgsConstructor
public class CustomGrantedAuthority implements GrantedAuthority {
    private String autority;
    public CustomGrantedAuthority(Role role){
        this.autority = role.getValue();
    }
    @Override
    public String getAuthority() {
        return autority;
    }
}
