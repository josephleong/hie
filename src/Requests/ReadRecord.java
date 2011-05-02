package Requests;

/**
 * The request to read a EHR record from either a HISP user or the PHR patient
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class ReadRecord extends Request {
	private String recordId;
	private String type;
	private String agentId;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public ReadRecord(String recordId, String type) {
		this.type = type;
		this.recordId = recordId;
	}

	public ReadRecord(String recordId, String type, String agentId) {
		this.type = type;
		this.recordId = recordId;
		this.agentId = agentId;
	}

	public void setRecordId(String recordId) {
		this.recordId = recordId;
	}

	public String getRecordId() {
		return recordId;
	}

	public void setAgentId(String agentId) {
		this.agentId = agentId;
	}

	public String getAgentId() {
		return agentId;
	}

}