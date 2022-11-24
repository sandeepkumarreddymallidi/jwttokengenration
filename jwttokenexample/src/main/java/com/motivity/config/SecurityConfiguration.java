package com.motivity.config;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.motivity.filter.JWTFilter;
import com.motivity.service.UserService;
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
	@Autowired
 private UserService userService;
	@Autowired
	private JWTFilter jwtfilter;

@Override
public void configure(AuthenticationManagerBuilder auth) throws Exception {
	auth.userDetailsService(userService);
}

@Bean
public AuthenticationManager authentications(AuthenticationManagerBuilder auth) throws Exception {
	
	
	return super.authenticationManagerBean();
}
@Override
protected void configure(HttpSecurity http) throws Exception {
	http.csrf().disable().authorizeRequests().antMatchers("/authenticate").permitAll()
	.anyRequest().authenticated().and().sessionManagement()
	.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	http.addFilterBefore(jwtfilter, UsernamePasswordAuthenticationFilter.class);
}


}
