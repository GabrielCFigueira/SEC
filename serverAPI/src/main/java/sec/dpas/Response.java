package sec.dpas;


import java.util.ArrayList;
import java.io.Serializable;


public class Response implements Serializable {

	private String _statusCode;
	private ArrayList<Announcement> _announcements;
	private long _clientNonce;
	private long _serverNonce;
	private byte[] _signature;


	public Response(String statusCode, ArrayList<Announcement> announcements, long clientNonce, byte[] signature) {
		_statusCode = statusCode;
		_announcements = announcements;
		_clientNonce = clientNonce;
		_signature = signature;
	}

	public Response(String statusCode, long clientNonce, long serverNonce, byte[] signature) {
		_statusCode = statusCode;
		_clientNonce = clientNonce;
		_serverNonce = serverNonce;
		_signature = signature;
	}

	public String getStatusCode() { return _statusCode; }
	public ArrayList<Announcement> getAnnouncements() { return _announcements; }
	public long getClientNonce() { return _clientNonce; }
	public long getServerNonce() { return _serverNonce; }
	public byte[] getSignature() { return _signature; }

	public String toString(){ return _statusCode; }
}
