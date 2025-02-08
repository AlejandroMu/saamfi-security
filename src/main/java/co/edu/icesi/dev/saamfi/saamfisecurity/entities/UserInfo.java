package co.edu.icesi.dev.saamfi.saamfisecurity.entities;

public class UserInfo {

    private String email;
	private String documentId;
	private String username;
	private String name;
	private String lastname;
	private String phone;
	private String password;	
	private Long  institution;
	private String institutionName;
	private Long system;
	private String isActive;
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getDocumentId() {
        return documentId;
    }
    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getLastname() {
        return lastname;
    }
    public void setLastname(String lastname) {
        this.lastname = lastname;
    }
    public String getPhone() {
        return phone;
    }
    public void setPhone(String phone) {
        this.phone = phone;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public Long getInstitution() {
        return institution;
    }
    public void setInstitution(Long institution) {
        this.institution = institution;
    }
    public String getInstitutionName() {
        return institutionName;
    }
    public void setInstitutionName(String institutionName) {
        this.institutionName = institutionName;
    }
    public Long getSystem() {
        return system;
    }
    public void setSystem(Long system) {
        this.system = system;
    }
    public String getIsActive() {
        return isActive;
    }
    public void setIsActive(String isActive) {
        this.isActive = isActive;
    }

    
}