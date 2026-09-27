### 1. Data Integrity via Merkle Trees (SHA-256)
To ensure a document remains unaltered, the system utilizes a Merkle Tree. The document is divided into discrete data blocks (Leaves), which are hashed and paired until a single **Root Hash** is generated. If a single bit of the original document changes, the Root Hash changes entirely.

**Document Hashes:**
```text
SHA-256:  4f8c b2e7 9d3a 6f14 8c2b 7e19 3a5d 9c0f 2b6e 8a1d
          7c3f 9b4e 6a2d 1f7c 8b3e 5d9a 0c1e 2b7d 6f3a 9e1b
...
