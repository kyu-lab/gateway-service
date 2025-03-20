package kyulab.gatewayserver.domain;

public enum TokenStatus {
	OK, 		// 유효한 토큰
	EXPIRING,	// 유효기간 임박 (새로운 액세스 토큰 필요)
	EXPIRED,  	// 유효기간 만료
	INVALID,  	// 파싱 불가 (잘못된 토큰)
	MISSING, 	// 토큰이 누락됨
	ERROR		// 알수없는 유형
}
