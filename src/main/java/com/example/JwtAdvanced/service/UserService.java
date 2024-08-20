package com.example.JwtAdvanced.service;

import com.example.JwtAdvanced.dto.JoinDto;
import com.example.JwtAdvanced.entity.User;
import com.example.JwtAdvanced.repository.UserRepository;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Getter
@Setter
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public boolean join(JoinDto joinDto){
        String username=joinDto.getUsername();
        String password=joinDto.getPassword();

        boolean isExist=userRepository.existsByUsername(username);
        if(isExist){
            return false;
        }
        User data=new User();
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
        return true;
    }

    public String userInfo(String username) {
        return username;
    }
}
