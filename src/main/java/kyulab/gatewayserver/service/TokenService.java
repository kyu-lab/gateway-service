package kyulab.gatewayserver.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import kyulab.gatewayserver.util.SecretUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

	private final SecretUtil secretUtil;

	public boolean validateToken(String token) throws JwtException {
		try {
			if (!token.startsWith("Bearer ")) {
				return false;
			}
			token = token.substring(7);
			Jws<Claims> claims = Jwts.parserBuilder()
					.setSigningKey(secretUtil.getSecretKey())
					.build().parseClaimsJws(token);
			Date tokenExpiered = claims.getBody().getExpiration();
			return tokenExpiered.after(new Date());
		} catch (JwtException e) {
			log.error("Invalid token : " + e.getMessage());
			return false;
		}
	}

}
