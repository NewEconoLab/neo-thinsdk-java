package neo;

import lombok.Data;

@Data
public class TransactionInput {
    private byte[] hash;
    private short index;
}
