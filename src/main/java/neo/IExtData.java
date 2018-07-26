package neo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public interface IExtData {
    public void Serialize(Transaction tx, ByteArrayOutputStream baos);
    public void Deserialize(Transaction tx, ByteArrayInputStream bais);
}
