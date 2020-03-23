package sec.dpas;


import java.sql.Timestamp;

import java.util.ArrayList;

public class Response {

	private String _statusCode;
	private ArrayList<Announcement> _announcements;
	private Timestamp _ts;
	private byte[] _signature;


	public Response(String statusCode, ArrayList<Announcement> announcements, Timestamp ts, byte[] signature) {
		_statusCode = statusCode;
		_announcements = announcements;
		_ts = ts;
		_signature = signature;
	}

	public String getStatusCode() { return _statusCode; }
	public ArrayList<Announcement> getAnnouncements() { return _announcements; }
	public Timestamp getTimestamp() { return _ts; }
	public byte[] getSignature() { return _signature; }
}
