package login.loginJWT.controller;


import login.loginJWT.config.auth.PrincipalDetails;
import login.loginJWT.model.Users;
import login.loginJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpSession;
import java.util.List;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class RestApiController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// All user access
	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}

	@GetMapping("/logout")
	public String logout(HttpSession session) {
		session.invalidate();
		return "logout";
	}

	@GetMapping("/user")
	public PrincipalDetails user(Authentication authentication) {
		PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principal : "+principal.getUser().getId());
		System.out.println("principal : "+principal.getUser().getUsername());
		System.out.println("principal : "+principal.getUser().getPassword());

		return principal;
	}

	// Admin user access
	@GetMapping("/admin/users")
	public List<Users> users(){
		return userRepository.findAll();
	}

	@PostMapping("/join")
	public String join(@RequestBody Users user) throws Exception {
		Users userCheck = userRepository.findByUsername(user.getUsername());

		if (userCheck != null) {
			throw new Exception("exception");
		}

		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "completed";
	}

}











