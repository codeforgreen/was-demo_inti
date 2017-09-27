package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.
                authorizeRequests().antMatchers("/static/**", "/", "/login").permitAll();
        http.formLogin().loginPage("/login").permitAll();
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder amb) throws Exception {
        amb.eraseCredentials(false)
                .inMemoryAuthentication()
                .withUser("user")
                .password("$2a$10$KJhOzmLH8f51SVbuPVAq4OloN4eYnI7tYzwbOkb43SUr2XJ0IrucS").authorities("USER")
                .and().passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
