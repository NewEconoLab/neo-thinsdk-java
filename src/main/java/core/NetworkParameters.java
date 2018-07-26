package core; /**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



import java.io.Serializable;



/**
 * <p>core.NetworkParameters contains the data needed for working with an instantiation of a Litecoin chain.</p>
 *
 * Currently there are only two, the production chain and the test chain. But in future as Litecoin
 * evolves there may be more. You can create your own as long as they don't conflict.
 */
public class NetworkParameters implements Serializable {
    private static final long serialVersionUID = 3L;


    public final int addressHeader = 0x17;
    /** First byte of a base58 encoded dumped private key. See {@link DumpedPrivateKey}. */
    public final int dumpedPrivateKeyHeader = 0x80;

    public final int privateSentinel = 0x01;
}
