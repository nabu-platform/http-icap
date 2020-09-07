package be.nabu.libs.http.icap;

public class VirusInfection {
	private String type, resolution, threat;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getResolution() {
		return resolution;
	}

	public void setResolution(String resolution) {
		this.resolution = resolution;
	}

	public String getThreat() {
		return threat;
	}

	public void setThreat(String threat) {
		this.threat = threat;
	}
	
	@Override
	public String toString() {
		return threat + " (type=" + type + ", resolution=" + resolution + ")";
	}
}
