# InvisiBits

A tiny Flask app that demonstrates practical digital forensics workflows for images and audio. It lets you encode, decode, and detect LSB steganography in PNG/JPG pictures or WAV audio, adds optional password protection, compresses text so longer payloads fit, and delivers decoded messages as downloadable `.txt` files.

## Author
- Markus Stamm

## Educational Use Only

This project is for education and defensive learning only. Use it to understand steganography and forensic limits, not to hide harmful content or bypass rules.

## Features
- **Image steganography**: LSB encoder/decoder for PNG and JPG (≤5 MB) with automatic `_steg` filename suffix.
- **Audio steganography**: Embed/recover text inside 8/16-bit WAV files (≤10 MB).
- **Compression + lock**: UTF-8 text is zlib-compressed (unless you uncheck the new “disable compression” option), then optionally XOR-encrypted with a SHA-256 derived key from the provided password.
- **Detection mode**: Quick heuristic that inspects LSB balance/transitions to flag images that likely contain hidden content.
- **Message export**: Decoded text is shown inline and can be downloaded as `decoded_message.txt` with one click.
- **Single-page UI**: Pure HTML + CSS interface; results open in a lightweight summary view.

## Run with Docker
Docker is the only requirement.

```bash
docker build -t invisibits . && docker run --rm -p 5000:5000 invisibits
```

Then browse to [http://localhost:5000](http://localhost:5000).

## Usage
1. **Encode image**: Upload a PNG/JPG cover image, type a secret, optionally set a password, and download the `_steg` file.
2. **Decode image**: Upload any stego image, supply the password if it was locked, read the message, and download it as `.txt` if needed.
3. **Detection**: Drop any suspect image in the detector to see a qualitative “unlikely / possible / high likelihood” verdict based on LSB noise.
4. **Audio encode/decode**: Follow the same flow with WAV files (mono or stereo, 8/16-bit PCM).
5. **Compression comparison**: During either encode flow, check “Disable compression” to embed raw UTF-8 bytes. This inflates the payload so you can demonstrate how compression increases capacity; simply run the same message with the box unchecked to compare download sizes.

> **Tip:** Larger media files allow longer messages. If you hit the “message is too large” warning, either shorten the text or pick a higher-resolution cover.

## Implementation notes
- Text is compressed before embedding so you can fit noticeably longer content in the same carrier.
- Password protection uses a simple XOR stream derived from `SHA-256(password)`; wrong passwords prevent decompression.
- Every payload stores a magic header so decoding can signal when the given file does not contain an InvisiBits message.
- The detection feature is heuristic-only; it should be treated as a quick triage signal, not forensic proof.
