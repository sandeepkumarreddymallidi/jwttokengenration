package com.motivity.service;

import java.util.ArrayList;


import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
@Service
public class UserService implements UserDetailsService{

	
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		return new User("admin","password",new ArrayList<>());
	}
}
