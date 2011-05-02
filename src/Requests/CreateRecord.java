package Requests;

/**
 * The request to Create a record for a HISP agent
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
@SuppressWarnings("serial")
public class CreateRecord extends Request {
	private String userId;
	private String owner;
	private String name;
	private String age;
	private String weight;
	private String prescriptions;
	private String other;
	private String diagnosis;
	private byte[] key;
	
	public CreateRecord(String userId, String owner, String name, String age,
			String weight, String prescriptions, String other,
			String diagnosis, byte[] key) {
		super();
		this.userId = userId;
		this.owner = owner;
		this.name = name;
		this.age = age;
		this.weight = weight;
		this.prescriptions = prescriptions;
		this.other = other;
		this.diagnosis = diagnosis;
		this.key = key;
	}

	public CreateRecord(String userId, String owner, String name, String age,
			String weight, String prescriptions, String other, String diagnosis) {
		super();
		this.userId = userId;
		this.owner = owner;
		this.name = name;
		this.age = age;
		this.weight = weight;
		this.prescriptions = prescriptions;
		this.other = other;
		this.diagnosis = diagnosis;
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

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getAge() {
		return age;
	}

	public void setAge(String age) {
		this.age = age;
	}

	public String getWeight() {
		return weight;
	}

	public void setWeight(String weight) {
		this.weight = weight;
	}

	public String getPrescriptions() {
		return prescriptions;
	}

	public void setPrescriptions(String prescriptions) {
		this.prescriptions = prescriptions;
	}

	public String getOther() {
		return other;
	}

	public void setOther(String other) {
		this.other = other;
	}

	public String getDiagnosis() {
		return diagnosis;
	}

	public void setDiagnosis(String diagnosis) {
		this.diagnosis = diagnosis;
	}

	public byte[] getKey() {
		return key;
	}

	public void setKey(byte[] key) {
		this.key = key;
	}
	
}