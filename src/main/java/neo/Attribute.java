package neo;

import lombok.Data;

@Data
public class Attribute {
    private byte usage;
    private byte[] data;
}
