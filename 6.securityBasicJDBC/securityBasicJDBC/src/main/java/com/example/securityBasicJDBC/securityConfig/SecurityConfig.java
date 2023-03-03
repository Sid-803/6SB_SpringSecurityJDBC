package com.example.securityBasicJDBC.securityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource) //create database connection
                .usersByUsernameQuery("Select user_name,user_pwd,user_enabled from user where user_name=?")
                .authoritiesByUsernameQuery("Select user_name, user_role from user where user_name=?")
                .passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/home").permitAll()
                .antMatchers("/welcome").authenticated()
                .antMatchers("/admin").hasAuthority("ADMIN")
                .antMatchers("/EMPLOYEE").hasAuthority("EMPLOYEE")
                .antMatchers("/MANAGER").hasAuthority("MANAGER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .defaultSuccessUrl("/welcome",true)
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and()
                .exceptionHandling()
                .accessDeniedPage("/accessDenied");
    }
}
