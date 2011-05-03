package Requests;

/**
 * The request to read a EHR record from either a HISP user or the PHR patient
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */

@SuppressWarnings("serial")
public class RAReadRecord extends ReadRecord {
	private String columns;
	private String conditions;
	
	public RAReadRecord(String recordId, String type, String agentId, String columns, String conditions) {
		super(recordId, type, agentId);
		this.setColumns(columns);
		this.setConditions(conditions);
	}
	
	public RAReadRecord(ReadRecord rr, String col, String cond){
		super(rr.getRecordId(), rr.getType(), rr.getAgentId());
		this.setColumns(col);
		this.setConditions(cond);
	}

	public void setConditions(String conditions) {
		this.conditions = conditions;
	}

	public String getConditions() {
		return conditions;
	}

	public void setColumns(String columns) {
		this.columns = columns;
	}

	public String getColumns() {
		return columns;
	}
	

}