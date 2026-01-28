package at.itkollegimst.studentenverwaltung.controller;

import at.itkollegimst.studentenverwaltung.security.JwtService;
import at.itkollegimst.studentenverwaltung.security.RefreshTokenService;
import at.itkollegimst.studentenverwaltung.security.dto.LoginRequest;
import at.itkollegimst.studentenverwaltung.security.dto.RefreshRequest;
import at.itkollegimst.studentenverwaltung.security.dto.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

// TODO: Kompletten Authentication-Controller erstellen
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://127.0.0.1:5500")
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    public AuthController(JwtService jwtService,
                          RefreshTokenService refreshTokenService,
                          AuthenticationManager authenticationManager) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManager = authenticationManager;
    }

    // Quelle: https://www.javacodegeeks.com/2025/05/how-to-secure-rest-apis-with-spring-security-and-jwt-2025-edition.html
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshRequest request) { // TODO: RefreshRequest adden
        String refreshToken = request.getRefreshToken();
        if (!refreshTokenService.isValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String newAccessToken = jwtService.generateToken(request.getUsername());
        return ResponseEntity.ok(new TokenResponse(newAccessToken));
    }

    // TODO: Login-Methode adden
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) { // TODO: LoginRequest adden
        try {
            // Authentifizierung mit Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            String accessToken = jwtService.generateToken(loginRequest.getUsername());
            String refreshToken = refreshTokenService.generateRefreshToken(loginRequest.getUsername());
            return ResponseEntity.ok(new TokenResponse(accessToken, refreshToken));

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}

/*
Typischer Workflow:
1. Login → Access Token (15 Min) + Refresh Token (30 Tage)
2. API-Aufruf mit Access Token
3. Access Token läuft ab (401 Unauthorized)
4. Refresh-Aufruf mit Refresh Token → Neuer Access Token
5. API-Aufruf mit neuem Access Token

### Login
POST http://localhost:8080/api/auth/login
Content-Type: application/json

{
  "username": "user",
  "password": "password"
}

### Geschützter Aufruf
GET http://localhost:8080/api/v1/studenten
Authorization: Bearer <accessToken>

### Token erneuern
POST http://localhost:8080/api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{{refreshToken}}",
  "username": "user"
}
 */