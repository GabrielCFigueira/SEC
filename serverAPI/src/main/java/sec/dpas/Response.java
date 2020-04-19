package sec.dpas;


import java.util.ArrayList;
import java.io.Serializable;


public class Response implements Serializable {

	private String _statusCode;
	private ArrayList<Announcement> _announcements;
	private String _clientNonce;
	private String _serverNonce;
	private byte[] _signature;


	public Response(String statusCode, ArrayList<Announcement> announcements, String clientNonce, byte[] signature) {
		_statusCode = statusCode;
		_announcements = announcements;
		_clientNonce = clientNonce;
		_signature = signature;
	}

	public Response(String statusCode, String clientNonce, String serverNonce, byte[] signature) {
		_statusCode = statusCode;
		_clientNonce = clientNonce;
		_serverNonce = serverNonce;
		_signature = signature;
	}

	public String getStatusCode() { return _statusCode; }
	public ArrayList<Announcement> getAnnouncements() { return _announcements; }
	public String getClientNonce() { return _clientNonce; }
	public String getServerNonce() { return _serverNonce; }
	public byte[] getSignature() { return _signature; }

	public String toString(){ return _statusCode; }
}
