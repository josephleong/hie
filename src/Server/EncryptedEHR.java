package Server;

@SuppressWarnings("serial")
public class EncryptedEHR extends Reply{
	
	private String userId;
	private String owner;
	private byte[] name; 
	private byte[] age; 
	private byte[] weight;
	private byte[] diagnosis;
	private byte[] prescriptions;
	private byte[] other;
	
	
	public EncryptedEHR(String userId, String owner, byte[] name, byte[] age, byte[] weight, byte[] diagnosis, byte[] prescriptions, byte[] other) {
		super("Successful Retrieval");
		this.userId = userId;
		this.owner = owner;
		this.name = name; 
		this.age = age; 
		this.weight = weight;
		this.diagnosis = diagnosis;
		this.prescriptions = prescriptions;
		this.other = other;
	}


	public String getUserId() {
		return userId;
	}


	public void setUserId(String userId) {
		this.userId = userId;
	}


	public String getOwner() {
		return owner;
	}


	public void setOwner(String owner) {
		this.owner = owner;
	}


	public byte[] getName() {
		return name;
	}


	public void setName(byte[] name) {
		this.name = name;
	}


	public byte[] getAge() {
		return age;
	}


	public void setAge(byte[] age) {
		this.age = age;
	}


	public byte[] getWeight() {
		return weight;
	}


	public void setWeight(byte[] weight) {
		this.weight = weight;
	}


	public byte[] getDiagnosis() {
		return diagnosis;
	}


	public void setDiagnosis(byte[] diagnosis) {
		this.diagnosis = diagnosis;
	}


	public byte[] getPrescriptions() {
		return prescriptions;
	}


	public void setPrescriptions(byte[] prescriptions) {
		this.prescriptions = prescriptions;
	}


	public byte[] getOther() {
		return other;
	}


	public void setOther(byte[] other) {
		this.other = other;
	}


		
}
