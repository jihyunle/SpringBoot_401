package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/* these annots indicate to compiler that file is a config file, and SpringSecurity is enabled*/
@Configuration
@EnableWebSecurity
public class SecurityConfiguration  extends WebSecurityConfigurerAdapter {

    @Bean // creates an object that can be reused to encode pw in your app
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); // provides an instance of BCPE, a pw encoder
    }

    @Autowired
    private SSUserDetailsService userDetailsService;

    @Autowired
    private UserRepository appUserRepository;

    @Override
    public UserDetailsService userDetailsServiceBean() throws
            Exception {
            return new SSUserDetailsService(appUserRepository);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{ // this fuctn overrides the default config method
        http
                .authorizeRequests() // tells the app which request should be authorized
                .antMatchers("/", "/h2-console/**", "/register").permitAll()
//                .access("hasAnyAuthority('USER','ADMIN')")
//                .antMatchers("/admin").access("hasAuthority('ADMIN')")
                .anyRequest().authenticated() // here we're saying any request that is authenticated is permitted
                .and() // additional rules below
                .formLogin().loginPage("/login").permitAll() // .formLogin() indicates that app should show login form
                // above line means you are expecting a login form, which will display when you visit the route /login,
                // and everyone can see it, even if not authenticated
                .and()
                .logout()
                .logoutRequestMatcher(
                        new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login").permitAll()
                .and()
                .httpBasic();
        http
                .csrf().disable();
        http
                .headers().frameOptions().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception
    {   // this fuctn configures the users who can access the app
            auth.userDetailsService(userDetailsServiceBean())
                    .passwordEncoder(passwordEncoder());


//            auth.inMemoryAuthentication()
//                    .withUser("dave").password(passwordEncoder().encode("begreat"))
//                        .authorities("ADMIN")
//                    .and()
//                    .withUser("User").password(passwordEncoder().encode("password"))
//                        .authorities("USER")
//                        .and().passwordEncoder(passwordEncoder()); // is this right? should it be encoder inside paranthesis?

    }
}
