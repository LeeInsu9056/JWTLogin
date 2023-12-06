package login.loginJWT.config.jwt;

public interface JwtProperties {
	String SECRET = "loose"; // Private key
	int EXPIRATION_TIME = 10000; // 10 seconds
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
