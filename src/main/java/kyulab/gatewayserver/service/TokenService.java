package kyulab.gatewayserver.service;

import io.jsonwebtoken.*;
import kyulab.gatewayserver.domain.TokenStatus;
import kyulab.gatewayserver.util.SecretUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

	private final SecretUtil secretUtil;
	private final StringRedisTemplate redisTemplate;

	/**
	 * 전달받은 토큰의 유효성 검사를 한다.
	 * @param token 토큰값
	 * @param isAccess 액세스 토큰 여부 (false일 경우 리프레쉬 토큰)
	 * @return TokenStatus 현재 사용중이 토큰의 상태값
	 * @throws JwtException 토큰이 정상적이지 않을 경우
	 */
	public TokenStatus validateToken(String token, boolean isAccess) throws JwtException {
		try {
			SecretKey signingKey = isAccess ? secretUtil.getAccessKey() : secretUtil.getRefreshKey();
			Jws<Claims> claims = Jwts.parserBuilder()
					.setSigningKey(signingKey)
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

	public String getSubject(String token) {
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

	public boolean hasRefreshToken(String userId) {
		return redisTemplate.hasKey("refresh-" + userId);
	}

	public boolean validRefreshToken(String refreshToken, String userId) {
		String storeRefreshToken = redisTemplate.opsForValue().get("refresh-" + userId);
		TokenStatus status = validateToken(storeRefreshToken, false);
		if (TokenStatus.OK != status) {
			return false;
		}
		return refreshToken.equals(storeRefreshToken);
	}

}
