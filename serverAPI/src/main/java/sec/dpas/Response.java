package sec.dpas;


import java.sql.Timestamp;

public class Response {

	private String _statusCode;
	private Announcement[] _announcements; 
	private Timestamp _ts;
	private byte[] _signature;
	

	public Response(String statusCode, Announcement[] announcements, Timestamp ts, byte[] signature) {
		_statusCode = statusCode;
		_announcements = announcements;
		_ts = ts;
		_signature = signature;
	}

	public String getStatusCode() { return _statusCode; }
	public Announcement[] getAnnouncements() { return _announcements; }
	public Timestamp getTimestamp() { return _ts; }
	public byte[] getSignature() { return _signature; }
}
