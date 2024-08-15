package com.example.JwtAdvanced.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry){

        //모든 컨트롤러에 대해 http://localhost:3000에서 오는 요청을 허용해줌
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }
}
