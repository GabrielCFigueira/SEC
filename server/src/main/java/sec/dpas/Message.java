package sec.dpas;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

public class Message {

	private byte[] _byteArray;

	public byte[] getByteArray() { return _byteArray; }

	public void appendObject(Object obj) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(bos);
		out.writeObject(obj);
		out.flush();

		byte[] array = bos.toByteArray();

		out.close();

		bos = new ByteArrayOutputStream();
		bos.write(_byteArray);
		bos.write(array);
		_byteArray = bos.toByteArray();
	}
}
