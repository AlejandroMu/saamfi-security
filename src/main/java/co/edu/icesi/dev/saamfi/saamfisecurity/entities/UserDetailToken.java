package co.edu.icesi.dev.saamfi.saamfisecurity.entities;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailToken implements UserDetails {
    
    private String username;
    private int system;
    private String persId;
    private Collection<SimpleGrantedAuthority> roles;

    public UserDetailToken(String username, int system, String persId, Collection<SimpleGrantedAuthority> roles) {
        this.username = username;
        this.system = system;
        this.persId = persId;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }
    @Override
    public String getPassword() {
        return "";
    }
    @Override
    public String getUsername() {
        return username;
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }

    public int getSystem() {
        return system;
    }

    public String getPersId() {
        return persId;
    }

    @Override
    public String toString() {
        return "UserDetailToken [persId=" + persId + ", roles=" + roles + ", system="
                + system + ", username=" + username + "]";
    }

}
