package co.edu.icesi.dev.saamfi.saamfisecurity.entities;

public class LoginResponse {
    private long userId;
	private String userUsername;
	private String userExtId;
	private String userEmail;
	private String userPhone;
	private String userName;
	private String userLastname;
	private String userDocumentId;

	private String accessToken;
	private String tokenType;

	private String systemHomePage;

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public String getUserUsername() {
        return userUsername;
    }

    public void setUserUsername(String userUsername) {
        this.userUsername = userUsername;
    }

    public String getUserExtId() {
        return userExtId;
    }

    public void setUserExtId(String userExtId) {
        this.userExtId = userExtId;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getUserPhone() {
        return userPhone;
    }

    public void setUserPhone(String userPhone) {
        this.userPhone = userPhone;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserLastname() {
        return userLastname;
    }

    public void setUserLastname(String userLastname) {
        this.userLastname = userLastname;
    }

    public String getUserDocumentId() {
        return userDocumentId;
    }

    public void setUserDocumentId(String userDocumentId) {
        this.userDocumentId = userDocumentId;
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
