package kyulab.gatewayserver.service;

import io.jsonwebtoken.*;
import kyulab.gatewayserver.domain.TokenStatus;
import kyulab.gatewayserver.util.SecretUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

	private final SecretUtil secretUtil;

	public TokenStatus validateAccessToken(String token) throws JwtException {
		try {
			Jws<Claims> claims = Jwts.parserBuilder()
					.setSigningKey(secretUtil.getAccessKey())
					.build()
					.parseClaimsJws(token);

			Date tokenExpiered = claims.getBody().getExpiration();
			long fiveMinutesInMillis = TimeUnit.MINUTES.toMillis(5);
			Date fiveMinutesLater = new Date(System.currentTimeMillis() + fiveMinutesInMillis);

			// 만료 시간이 5분 이내라면 새로운 토큰을 발급
			if (tokenExpiered.before(fiveMinutesLater)) {
				return TokenStatus.EXPIRING;
			}

			return TokenStatus.OK;
		} catch (ExpiredJwtException t) {
			return TokenStatus.EXPIRED;
		} catch (ClaimJwtException c) {
			log.warn("Invalid token : " + c.getMessage());
			return TokenStatus.INVALID;
		} catch (Exception e) {
			log.error("Jwt Error : " + e.getMessage());
			return TokenStatus.ERROR;
		}
	}

	public String parseToken(String token) {
		try {
			return Jwts.parserBuilder()
					.setSigningKey(secretUtil.getAccessKey())
					.build()
					.parseClaimsJws(token)
					.getBody()
					.getSubject();
		} catch (ExpiredJwtException e) {
			return e.getClaims().getSubject();
		} catch (JwtException j) {
			log.error("잘못된 토큰 : {}", j.getMessage());
			throw new IllegalArgumentException("Ivalid Token!");
		} catch (Exception e) {
			log.error("Jwt Error : " + e.getMessage());
			throw new RuntimeException("Jwt Error!");
		}
	}

}
