- **Question:** The student can explain the concept of steganography and its relevance to digital forensics.
- **Explanation:** Steganography hides data inside ordinary media files so the message is invisible. Investigators study it because suspects can smuggle evidence in harmless-looking photos or audio, so forensic tooling must both create and detect those hidden payloads.

- **Question:** The student can describe the Least Significant Bit (LSB) technique used in image steganography.
- **Explanation:** Each pixel channel (red, green, blue) stores values from 0–255. Changing only the least significant bit of those numbers flips the value by at most 1, so humans cannot see the difference, yet we can pack one secret bit into each color channel.

- **Question:** The student can explain the difference between steganography and encryption.
- **Explanation:** Encryption scrambles data so it looks random but still obvious that a secret exists; steganography keeps the surrounding file looking normal so observers do not even know a message is present. The app combines both: it hides the payload and can also encrypt it with a password.

- **Question:** Student can explain the efficiency of decoding and encoding algorithms.
- **Explanation:** Encoding and decoding walk each pixel (or audio sample) once and flip/read a single bit, so runtime is linear in the number of pixels or samples. That keeps the process fast even for large images because there are no nested heavy operations.

- **Question:** The student can explain the password-based encryption method used for encoding and decoding the hidden message.
- **Explanation:** The password is hashed with SHA-256 to make a fixed-length key. The compressed message bytes are XOR’d with that key stream while encoding, and XOR’d again with the same key to decrypt, so only someone who knows the password hash can recover the text.

- **Question:** The student can explain the compression algorithm used and its efficiency.
- **Explanation:** The tool uses zlib (DEFLATE), which quickly compresses UTF-8 text and is built into Python. Compression reduces payload size before embedding, meaning fewer pixels/samples need to be modified and longer messages can fit into the same carrier file.
