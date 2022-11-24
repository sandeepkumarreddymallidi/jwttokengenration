package com.motivity.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.motivity.service.UserService;
import com.motivity.utility.JWTUtility;
@Component
public class JWTFilter extends OncePerRequestFilter{
	@Autowired
	private JWTUtility jwtUtility;
	@Autowired
	private UserService userService;
	

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String autherization=request.getHeader("Authorization");
		String token=null;
		String username=null;
		if(null!=autherization && autherization.startsWith("Bearer ")) {
			token=autherization.substring(7);
			username=jwtUtility.getUsernameFromToken(token);
			System.out.println(username);
		}
		if(null!=username &&SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=userService.loadUserByUsername(username);
			System.out.println(userDetails.getPassword());
			if(jwtUtility.validateToken(token, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
				=new UsernamePasswordAuthenticationToken( userDetails, null,userDetails.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(
						new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		filterChain.doFilter(request, response);
		
	}

}
