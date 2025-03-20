package kyulab.gatewayserver.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kyulab.gatewayserver.ErrorResponse;
import kyulab.gatewayserver.domain.TokenStatus;
import kyulab.gatewayserver.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements GlobalFilter {

	private final TokenService tokenService;
	private final StringRedisTemplate redisTemplate;
	private final ObjectMapper objectMapper;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();

		// GET 요청은 공개경로로 인증없이 통과한다.
		if (request.getMethod().equals(HttpMethod.GET)) {
			return chain.filter(exchange);
		}

		// 사용자 로그인과 회원가입에는 인증없이 통과한다.
		String path = exchange.getRequest().getURI().getPath();
		if (path.startsWith("/api/users/login") || path.startsWith("/api/users/signUp")) {
			return chain.filter(exchange);
		}

		String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (!StringUtils.hasText(token)) {
			return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token Missing");
		}

		if (!token.startsWith("Bearer ")) {
			return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Please Header check again");
		}
		token = token.substring(7);


		/*
		 * 토큰 인증/인가 방법
		 * 1. 액세스 토큰이 있을 경우 통과
		 * 2. 리프레쉬 토큰이 있을 경우 액세스 토큰을 받도록 주소를 보냄
		 * 3. 리프레쉬 토큰이 없을 경우 접근을 금지
		 */
		// 토큰이 있는 사용자가 페이지에 다시 접속시 재로그인 시킨다.
		TokenStatus status = tokenService.validateAccessToken(token);
		return switch (status) {
			case MISSING, INVALID -> {
				log.info("잘못된 토큰 : {}", token);
				yield sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid Token");
			}
			case EXPIRED, EXPIRING -> {
				if (path.startsWith("/api/users/refresh") && request.getHeaders().getFirst("X-refresh-check").equals("true")) {
					yield chain.filter(exchange);
				}
				String userId = tokenService.parseToken(token);
				if (!redisTemplate.hasKey("refresh-" + userId)) {
					yield sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid Token");
				}

				// 토큰이 만료되었다면 다시 토큰을 발급받도록 주소를 보낸다.
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				exchange.getResponse().getHeaders().add("X-Refresh-URL", "/api/users/refresh?userId=" + userId);
				exchange.getResponse().getHeaders().add("Access-Control-Expose-Headers", "X-Refresh-URL");
				yield exchange.getResponse().setComplete();
			}
			case OK -> chain.filter(exchange);
			default -> {
				log.error("예상치 못한 토큰 상태: {}", status);
				yield sendErrorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Sever Can`t be Parsing Token : " + token);
			}
		};

	}

	private Mono<Void> sendErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
		exchange.getResponse().setStatusCode(status);
		exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
		ErrorResponse error = new ErrorResponse(message);
		try {
			byte[] jsonBytes = objectMapper.writeValueAsBytes(error);
			DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(jsonBytes);
			return exchange.getResponse().writeWith(Mono.just(buffer));
		} catch (JsonProcessingException e) {
			log.error("Error serializing response: {}", e.getMessage());
			return exchange.getResponse().setComplete();
		}
	}

}
