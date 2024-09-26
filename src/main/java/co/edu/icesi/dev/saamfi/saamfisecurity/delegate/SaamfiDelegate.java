package co.edu.icesi.dev.saamfi.saamfisecurity.delegate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.client.RestTemplate;

import co.edu.icesi.dev.saamfi.saamfisecurity.entities.LoginBody;
import co.edu.icesi.dev.saamfi.saamfisecurity.entities.LoginResponse;
import co.edu.icesi.dev.saamfi.saamfisecurity.entities.UserDetailToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

public class SaamfiDelegate {

    private static Logger logger = Logger.getLogger(SaamfiDelegate.class.getName());

    private static final String ROLE_KEYS = "role";

    private static final String SYSTEM_CLAIM = "system";

    private static final String USERNAME_CLAIM = "username";

    private static final String ID_CLAIM = "persId";

    private RestTemplate template;

    private PublicKey publicKey;

    private String saamfiUrl;

    private long systemId;

    public SaamfiDelegate(String saamfiUrl2, long systemId) {
        template = new RestTemplate();
        this.saamfiUrl = saamfiUrl2;
        this.systemId = systemId;

        try {
            publicKey = getPublicKey();

        } catch (Exception e) {
            e.printStackTrace();
        }
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
                (int) claims.get(SYSTEM_CLAIM), claims.get(ID_CLAIM).toString(),
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

    public LoginResponse getLoginResponseUserFromSaamfi(String username, String password) {
        try{
            ResponseEntity<?> response = template.postForEntity(saamfiUrl + "/public/authentication/login", new LoginBody(username, password, systemId),LoginResponse.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                LoginResponse loginResponse = (LoginResponse) response.getBody();
                return loginResponse;
            }
        }catch(Exception e){
            logger.warning("Error in the request: " + e.getMessage());
        }
        return null;
    }

    public String getUsersFromList(String authToken, List<Long> users) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(authToken);
            HttpEntity<List<Long>> entity = new HttpEntity<>(users, headers);
            ResponseEntity<String> response = template.exchange(saamfiUrl + "/users/users-from-list", HttpMethod.POST, entity, String.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                return (String) response.getBody();
            }
        } catch (Exception e) {
            logger.warning("Error in the request: " + e.getMessage());
        }
        return null;
    }

    public String getUsersByParamAndValue(String authToken, String param, String value) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(authToken);
            HttpEntity<Long> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = template.exchange(saamfiUrl + "/users?param=" + param + "&value=" + value, HttpMethod.GET, entity, String.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                return (String) response.getBody();
            }
        } catch (Exception e) {
            logger.warning("Error in the request: " + e.getMessage());
        }
        return null;
    }

}
