package com.openclassrooms.login.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig{
	
	/**
	 * Configure données de test
	 * @param auth
	 * @throws Exception
	 */
	@Bean
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		auth.inMemoryAuthentication()
		.withUser("springuser").password(passwordEncoder().encode("spring123")).roles("USER")
		.and()
		.withUser("springadmin").password(passwordEncoder().encode("admin123")).roles("ADMIN","USER");
	}
	
	/***
	 * Chaîne de filtrage des reqûetesq HTTP,
	 * verrouillant l'accès à certaines page en fonction de différents rôles
	 * @param http
	 * @return
	 * @throws Exception
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
		 .authorizeHttpRequests((requests) -> requests
				 .requestMatchers("/", "/home").permitAll()
				 .anyRequest().authenticated()
				 )
		 .formLogin((form) -> form
		 	.loginPage("/login")
		 	.permitAll()
		 )
		 .logout((logout) -> logout.permitAll());
		
		return http.build();
	}
	
	/***
	 * Hashage du mot de passe
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}