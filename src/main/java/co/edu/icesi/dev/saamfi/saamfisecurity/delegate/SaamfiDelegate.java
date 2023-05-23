package co.edu.icesi.dev.saamfi.saamfisecurity.delegate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

@Service
public class SaamfiDelegate {

    private static final String ROLE_KEYS = "role";

    private static final String INSTITUTION_CLAIM = "institution";

    private static final String SYSTEM_CLAIM = "system";

    private static final String USERNAME_CLAIM = "username";

    private RestTemplate template;

    private PublicKey publicKey;

    @Value("${saamfi.url}")
    private String saamfiUrl;

    public SaamfiDelegate() {
        template = new RestTemplate();
        try {
            publicKey = getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getUsernameFromJWT(String authToken) {

        Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken).getBody();
        String username = (String) claims.get(USERNAME_CLAIM);

        return username;
    }

    public long getSysIdFromJWT(String authToken) {
        Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken).getBody();
        int instId = (int) claims.get(SYSTEM_CLAIM);

        return instId;
    }

    public Collection<SimpleGrantedAuthority> getRolesFromJWT(String authToken) {
        final JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(publicKey).build();
        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(authToken);
        final Claims claims = (Claims) claimsJws.getBody();
        Stream<SimpleGrantedAuthority> stream = Arrays.stream(claims.get(ROLE_KEYS).toString().split(","))
                .map(SimpleGrantedAuthority::new);
        Collection<SimpleGrantedAuthority> authorities = null;
        try {
            authorities = stream.collect(Collectors.toList());
        } catch (Exception e) {
            authorities = Collections.emptyList();
        }
        return authorities;
    }

    public boolean validateToken(String authToken) {
        try {

            Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken);
            return true;

        } catch (MalformedJwtException ex) {
            System.out.println("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            System.out.println("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public UsernamePasswordAuthenticationToken getAuthentication(String authToken, Authentication authentication,
            UserDetails userDetails) {

        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        return new UsernamePasswordAuthenticationToken(userDetails, authToken.trim(), authorities);
    }

    public PublicKey getPublicKey() throws Exception {
        String key = template.getForEntity(saamfiUrl + "/public/publicKey", String.class).getBody();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getBytes());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);

    }

    public long getInstIdFromJWT(String authToken) {
        Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken).getBody();
        int instId = (int) claims.get(INSTITUTION_CLAIM);

        return instId;
    }
}
