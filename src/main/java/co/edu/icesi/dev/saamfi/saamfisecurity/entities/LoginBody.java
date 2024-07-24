package co.edu.icesi.dev.saamfi.saamfisecurity.entities;

public class LoginBody {
    private String username;
    private String password;
    private long sysid;

    public LoginBody(String username, String password, long sysid) {
        this.username = username;
        this.password = password;
        this.sysid = sysid;
    }

    public long getSysid() {
        return sysid;
    }
    
    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
