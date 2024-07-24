package co.edu.icesi.dev.saamfi.saamfisecurity.entities;

public class LoginResponse {
    private long id;
	private String username;
	private String email;
	private String phone;
	private String name;
	private String lastname;
	private String documentId;

	private String accessToken;
	private String tokenType;

	private String systemHomePage;

    public long getId() {
        return id;
    }

    public void setId(long userId) {
        this.id = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String userUsername) {
        this.username = userUsername;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String userEmail) {
        this.email = userEmail;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String userPhone) {
        this.phone = userPhone;
    }

    public String getName() {
        return name;
    }

    public void setName(String userName) {
        this.name = userName;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String userLastname) {
        this.lastname = userLastname;
    }

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String userDocumentId) {
        this.documentId = userDocumentId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getSystemHomePage() {
        return systemHomePage;
    }

    public void setSystemHomePage(String systemHomePage) {
        this.systemHomePage = systemHomePage;
    }

    
    
}
