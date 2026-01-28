package at.itkollegimst.studentenverwaltung.security;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Der RefreshTokenService verwendet derzeit eine In-Memory-Speicherung.
 * Für Produktivumgebungen sollte man eine Datenbank oder Redis (REmote DIctionary Server) verwenden.
 */
@Service
public class RefreshTokenService {

    private final Map<String, String> refreshTokenStore = new ConcurrentHashMap<>();
    private final JwtService jwtService;

    public RefreshTokenService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public String generateRefreshToken(String username) {
        String refreshToken = UUID.randomUUID().toString();
        refreshTokenStore.put(refreshToken, username);
        return refreshToken;
    }

    public boolean isValid(String refreshToken) {
        return refreshTokenStore.containsKey(refreshToken);
    }

    public String getUsernameFromToken(String refreshToken) {
        return refreshTokenStore.get(refreshToken);
    }

    public void invalidate(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }
}