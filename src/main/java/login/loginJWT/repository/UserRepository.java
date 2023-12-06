package login.loginJWT.repository;

import login.loginJWT.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users, Long>{
	Users findByUsername(String username);
}
