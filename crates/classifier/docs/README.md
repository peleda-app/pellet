# pellet-classifier

An online spam classifier with a fixed memory budget. No I/O: the host keeps the bytes.

- `Document`: subject, body text, link domains, sender domain, header names, symbols.
- `tokens(doc)`: prefixed tokens (`s:` subject words, `w:` body words, `b:` word pairs, `d:` link domains, `f:` sender domain, `h:` header names, `y:` symbols), lowercased, digit runs as `<length>`, unique, at most 4000. `TOKENIZER_VERSION` changes whenever they do.
- `Model`: FTRL-proximal logistic regression over tokens hashed (seeded FNV-1a) into 2^`bits` entries (16 to 24, default 18). Each entry is two `f32` accumulators, so memory is 8 bytes per entry, 2 MB by default, whatever the traffic. `predict` gives the probability of spam (0.5 untrained); `train` learns one document; `samples` counts ham and spam learned.
- `to_bytes` / `from_bytes`: a header (`PELLETM1`, tokenizer version, every parameter, sample counts) and the table, little endian. Another tokenizer version, a broken header or a wrong length is refused.

Defaults: `alpha` 0.2, `beta` 1.0, `l1` 0.1, `l2` 1.0. The tests train on invented spam and ham and require 98% right on messages the model did not see.
