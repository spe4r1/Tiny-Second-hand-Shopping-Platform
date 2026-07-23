# Tiny Second-hand Shopping Platform

시큐어코딩 과제용 중고거래 상점 웹앱입니다.

## 기능

### 회원 기능

- 회원가입
- 로그인
- 로그아웃
- 로그인 실패 횟수 제한
- 서버 세션 기반 사용자 인증

### 상품 기능

- 상품 목록 조회
- 상품 상세 조회
- 상품명, 설명, 지역 기반 검색
- 카테고리 필터
- 판매 상태 필터
- 판매 상품 등록
- 판매자 본인 상품 수정
- 판매 상태 변경
  - 판매중
  - 예약중
  - 판매완료

### 거래 기능

- 타인 상품 찜하기
- 찜 취소
- 장바구니 담기
- 장바구니 상품 삭제
- 구매 확정
- 주문 내역 조회
- 구매 완료 시 상품 자동 판매완료 처리

### 문의 기능

- 상품별 판매자 문의 작성
- 내가 보낸 문의 조회
- 내 상품에 들어온 문의 조회
- 관련 없는 사용자의 문의 조회 차단

### 내 상점 기능

- 내가 등록한 판매 상품 조회
- 내가 찜한 상품 조회
- 판매 상품 관리 화면 제공

### 보안 기능

- 비밀번호 PBKDF2-SHA256 해시 저장
- 세션 토큰 해시 저장
- CSRF 토큰 검증
- SQL Injection 방어
- Stored XSS 방어
- Reflected XSS 방어
- IDOR 방어
- Broken Access Control 방어
- 위험한 이미지 URL 스킴 차단
- 요청 본문 크기 제한
- 보안 헤더 적용
  - CSP
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy

## GitHub Repository

https://github.com/spe4r1/Tiny-Second-hand-Shopping-Platform
