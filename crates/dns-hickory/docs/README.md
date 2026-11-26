# pellet-dns-hickory

`HickoryResolver::new(&HickoryConfig)`: `Resolver` over hickory-resolver 0.26.

| Setting | Default | |
| --- | --- | --- |
| `nameservers` | system configuration | recursive resolvers on port 53, UDP and TCP; a local resolver is recommended because some DNS lists refuse public ones |
| `deadline` | 2 s | the longest one call may take, retries included; past it the call is `Timeout` |
| `cache_size` | 4096 | answers kept by hickory, positive and negative, for their TTL |

Names are validated and `.invalid` answered before anything is sent. Building the resolver sends nothing. Passes the offline conformance suite; nothing in its tests touches the network.
