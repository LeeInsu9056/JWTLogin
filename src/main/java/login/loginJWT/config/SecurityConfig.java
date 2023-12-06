package login.loginJWT.config;

import login.loginJWT.config.jwt.JwtAuthenticationFilter;
import login.loginJWT.config.jwt.JwtAuthorizationFilter;
import login.loginJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final AuthenticationConfiguration authenticationConfiguration;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private CorsConfig corsConfig;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager() throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				 .csrf(AbstractHttpConfigurer::disable)
				 .sessionManagement((sessionManagement) -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				 .formLogin(AbstractHttpConfigurer::disable)
				 .httpBasic(AbstractHttpConfigurer::disable)
				 .addFilter(new JwtAuthenticationFilter(authenticationManager()))
				 .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				 .authorizeRequests()
				 .requestMatchers("/api/v1/user/**")
				 .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				 .requestMatchers("/api/v1/admin/**")
				 .access("hasRole('ROLE_ADMIN')")
				 .anyRequest().permitAll()
				 .and().build();
	}

}






