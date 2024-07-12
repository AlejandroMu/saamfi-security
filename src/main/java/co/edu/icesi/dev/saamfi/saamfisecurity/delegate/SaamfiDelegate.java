package co.edu.icesi.dev.saamfi.saamfisecurity.delegate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import co.edu.icesi.dev.saamfi.saamfisecurity.filters.UserDetailToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

@Component
public class SaamfiDelegate {

    private static final String ROLE_KEYS = "role";

    private static final String INSTITUTION_CLAIM = "institution";

    private static final String SYSTEM_CLAIM = "system";

    private static final String USERNAME_CLAIM = "username";

    private static final String ID_CLAIM = "persId";

    private RestTemplate template;

    private PublicKey publicKey;

    private String saamfiUrl;

    public SaamfiDelegate(String saamfiUrl2) {
        template = new RestTemplate();
        this.saamfiUrl = saamfiUrl2;

        try {
            publicKey = getPublicKey();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public long getUserIdFromJWT(String authToken) {

        Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken).getBody();
        long userId = (long) claims.get(ID_CLAIM);

        return userId;
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

    public UserDetailToken validateToken(String authToken) {
        UserDetailToken userDetailToken = null;
        final Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken);
        final Claims claims = (Claims) claimsJws.getBody();
        userDetailToken = new UserDetailToken(claims.get(USERNAME_CLAIM).toString(),
                (int) claims.get(INSTITUTION_CLAIM), (int) claims.get(SYSTEM_CLAIM), claims.get(ID_CLAIM).toString(),
                getRolesFromJWT(authToken));
        return userDetailToken;

    }

    public UsernamePasswordAuthenticationToken getAuthentication(String authToken,
            UserDetails userDetails) {

        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        return new UsernamePasswordAuthenticationToken(userDetails, authToken.trim(), authorities);
    }

    public PublicKey getPublicKey() throws Exception {
        String key = template.getForEntity(saamfiUrl + "/public/publicKey", String.class).getBody();
        key = key.replace("[", "");
        key = key.replace("]", "");
        String split[] = key.split(",");
        byte[] bytes = new byte[split.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = Byte.parseByte(split[i].trim());

        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);

    }

    public long getInstIdFromJWT(String authToken) {
        Claims claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(authToken).getBody();
        int instId = (int) claims.get(INSTITUTION_CLAIM);

        return instId;
    }
}
