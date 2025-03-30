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
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements GlobalFilter {

	private final TokenService tokenService;
	private final ObjectMapper objectMapper;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();

		// GET 요청은 공개경로로 인증없이 통과한다.
		String path = exchange.getRequest().getURI().getPath();
		if (!path.startsWith("/api/users/refresh") && request.getMethod().equals(HttpMethod.GET)) {
			return chain.filter(exchange);
		}

		// api간 통신
		if (path.startsWith("/gateway")) {
			return chain.filter(exchange);
		}

		if (path.startsWith("/api/users/logout")) {
			return chain.filter(exchange);
		}

		// 사용자 로그인과 회원가입, 비밀번호 초기화는 인증없이 통과한다.
		if (path.startsWith("/api/users/login") || path.startsWith("/api/users/signup") || path.startsWith("/api/users/change/password")) {
			if (request.getCookies().containsKey("refresh-token")) {
				return sendErrorResponse(exchange, HttpStatus.BAD_REQUEST, "Already Login");
			}
			return chain.filter(exchange);
		}

		String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (!StringUtils.hasText(token)) {
			return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token Missing");
		}

		if (!token.startsWith("Bearer ")) {
			return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Please Header check again");
		}

		/*
		 * 토큰 인증/인가 방법
		 * 1. 액세스 토큰이 있을 경우 통과
		 * 2. 리프레쉬 토큰이 있을 경우 액세스 토큰을 받도록 주소를 보냄
		 * 3. 리프레쉬 토큰이 없을 경우 접근을 금지
		 */
		// 토큰이 있는 사용자가 페이지에 다시 접속시 재로그인 시킨다.
		token = token.substring(7);
		TokenStatus status;
		if (Objects.isNull(request.getHeaders().getFirst("X-Needs-Refresh"))) {
			status = tokenService.validateToken(token, true);
		} else {
			status = TokenStatus.REFRESH;
		}

		return switch (status) {
			case MISSING, INVALID -> {
				log.info("잘못된 토큰 : {}", token);
				yield sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid Token");
			}
			case EXPIRED, EXPIRING -> {
				String userId = tokenService.getSubject(token);

				// 리프레쉬 토큰이 없는 사용자는 재발급을 허용하지 않는다.
				if (!tokenService.hasRefreshToken(userId)) {
					yield sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Please login again");
				}

				// 토큰이 만료되었다면 다시 토큰을 발급받도록 주소를 보낸다.
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				yield exchange.getResponse().setComplete();
			}
			case OK -> chain.filter(exchange);
			case REFRESH -> {
				String userId = tokenService.getSubject(token);

				// 리프레쉬 토큰이 없는 사용자는 재발급을 허용하지 않는다.
				if (!tokenService.hasRefreshToken(userId)) {
					yield sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Please login again");
				}

				// 토큰 재요청 주소가 다를 경우
				if (!path.startsWith("/api/users/refresh")) {
					yield sendErrorResponse(exchange, HttpStatus.BAD_REQUEST, "Wrong request");
				}

				String refreshToken = request.getCookies().getFirst("refresh-token").getValue();
				if (!tokenService.validRefreshToken(refreshToken, userId)) {
					log.error("인증되지 않은 리프레쉬 토큰 : ${}", refreshToken);
					yield sendErrorResponse(exchange, HttpStatus.BAD_REQUEST, "Invalid Refresh Token!");
				}

				yield chain.filter(exchange);
			}
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
