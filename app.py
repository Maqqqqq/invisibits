import html
import io
import hashlib
import wave
import zlib
from typing import Generator, Iterable

from flask import Flask, Response, jsonify, render_template_string, request, send_file
from PIL import Image

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB to cover audio, but we enforce 5 MB for images

MAGIC = b"IB"
FLAG_LOCKED = 0x01
FLAG_COMPRESSED = 0x02
IMAGE_LIMIT = 5 * 1024 * 1024
AUDIO_LIMIT = 10 * 1024 * 1024


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()


def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_payload(message: str, password: str | None, *, compress: bool = True) -> bytes:
    if not message:
        raise ValueError("Message cannot be empty.")
    payload = message.encode("utf-8")
    if compress:
        payload = zlib.compress(payload)
    if password:
        payload = xor_with_key(payload, derive_key(password))
    flags = 0
    if password:
        flags |= FLAG_LOCKED
    if compress:
        flags |= FLAG_COMPRESSED
    return MAGIC + bytes([flags]) + payload


def recover_message(payload: bytes, password: str | None) -> str:
    if len(payload) < 3 or payload[:2] != MAGIC:
        raise ValueError("No InvisiBits payload detected.")
    flags = payload[2]
    legacy_format = flags in (0, 1)
    if legacy_format:
        requires_password = bool(flags)
        is_compressed = True
    else:
        requires_password = bool(flags & FLAG_LOCKED)
        is_compressed = bool(flags & FLAG_COMPRESSED)
    data = payload[3:]
    if requires_password:
        if not password:
            raise ValueError("Password required to unlock this message.")
        data = xor_with_key(data, derive_key(password))
    try:
        if is_compressed:
            message_bytes = zlib.decompress(data)
        else:
            message_bytes = data
        message = message_bytes.decode("utf-8")
    except zlib.error as exc:
        raise ValueError("Unable to decompress payload. Check your password.") from exc
    return message


def iter_image_lsbs(img: Image.Image) -> Generator[int, None, None]:
    pixels = img.load()
    width, height = img.size
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            yield r & 1
            yield g & 1
            yield b & 1


def embed_payload_in_image(img: Image.Image, payload: bytes) -> None:
    bits = _payload_to_bits(payload)
    pixels = img.load()
    width, height = img.size
    total_slots = width * height * 3
    if len(bits) > total_slots:
        max_payload_bytes = max((total_slots // 8) - 4, 0)
        raise ValueError(
            f"Message needs {len(bits)} LSB writes but this image only has {total_slots}. "
            f"Max payload is about {max_payload_bytes} bytes before compression."
        )

    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= len(bits):
                return
            r, g, b = pixels[x, y]
            if idx < len(bits):
                r = (r & ~1) | bits[idx]
                idx += 1
            if idx < len(bits):
                g = (g & ~1) | bits[idx]
                idx += 1
            if idx < len(bits):
                b = (b & ~1) | bits[idx]
                idx += 1
            pixels[x, y] = (r, g, b)


def _payload_to_bits(payload: bytes) -> list[int]:
    length = len(payload).to_bytes(4, "big")
    data = length + payload
    bits: list[int] = []
    for byte in data:
        bits.extend((byte >> shift) & 1 for shift in range(7, -1, -1))
    return bits


def extract_payload_from_image(img: Image.Image) -> bytes:
    bit_stream = iter_image_lsbs(img)
    length_bytes = _read_bytes(bit_stream, 4)
    length = int.from_bytes(length_bytes, "big")
    if length <= 0:
        raise ValueError("No payload found.")
    payload = _read_bytes(bit_stream, length)
    return payload


def _read_bytes(bit_stream: Iterable[int], length: int) -> bytes:
    iterator = iter(bit_stream)
    output = bytearray()
    for _ in range(length):
        byte = 0
        for _ in range(8):
            try:
                bit = next(iterator)
            except StopIteration as exc:
                raise ValueError("Payload truncated. The image may be corrupted.") from exc
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


def hide_message_in_image(
    data: bytes, message: str, password: str | None, fmt: str, *, compress: bool
) -> bytes:
    payload = build_payload(message, password, compress=compress)
    with Image.open(io.BytesIO(data)) as img:
        img = img.convert("RGB")
        embed_payload_in_image(img, payload)
        buffer = io.BytesIO()
        img.save(buffer, format=fmt)
    buffer.seek(0)
    return buffer.read()


def extract_message_from_image(data: bytes, password: str | None) -> str:
    with Image.open(io.BytesIO(data)) as img:
        img = img.convert("RGB")
        payload = extract_payload_from_image(img)
    return recover_message(payload, password)


def analyze_image_for_stego(data: bytes) -> str:
    with Image.open(io.BytesIO(data)) as img:
        img = img.convert("RGB")
        lsb_values = list(iter_image_lsbs(img))
    if len(lsb_values) < 2:
        return "Image does not have enough data for analysis."
    ones = sum(lsb_values)
    balance = ones / len(lsb_values)
    transitions = sum(1 for i in range(1, len(lsb_values)) if lsb_values[i] != lsb_values[i - 1])
    transition_ratio = transitions / (len(lsb_values) - 1)
    # Simple heuristic: well-hidden payloads push balance and transitions near 0.5
    balance_score = abs(0.5 - balance)
    transition_score = abs(0.5 - transition_ratio)
    score = (balance_score + transition_score) / 2
    if score < 0.02:
        verdict = "High likelihood of hidden data."
    elif score < 0.05:
        verdict = "Possibly steganographic."
    else:
        verdict = "Unlikely to contain an LSB payload."
    return f"{verdict} Balance={balance:.3f}, transitions={transition_ratio:.3f}."


def _steg_download_name(filename: str, ext: str) -> str:
    base = filename or ""
    if "." in base:
        base = base.rsplit('.', 1)[0]
    if not base:
        base = "output"
    if base.lower().endswith("_steg"):
        normalized = base
    else:
        normalized = f"{base}_steg"
    return f"{normalized}.{ext.lower()}"


def embed_payload_in_audio(
    audio_bytes: bytes, message: str, password: str | None, *, compress: bool
) -> bytes:
    payload = build_payload(message, password, compress=compress)
    with wave.open(io.BytesIO(audio_bytes)) as wav:
        if wav.getsampwidth() not in (1, 2):
            raise ValueError("Only 8-bit or 16-bit WAV files are supported.")
        params = wav.getparams()
        frames = bytearray(wav.readframes(params.nframes))

    bits = _payload_to_bits(payload)
    samples = len(frames) // params.sampwidth
    if len(bits) > samples:
        max_payload_bytes = max((samples // 8) - 4, 0)
        raise ValueError(
            f"Message needs {len(bits)} samples but this file only exposes {samples}. "
            f"Max payload is about {max_payload_bytes} bytes before compression."
        )

    for idx, bit in enumerate(bits):
        byte_index = idx * params.sampwidth
        frames[byte_index] = (frames[byte_index] & ~1) | bit

    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as output:
        output.setparams(params)
        output.writeframes(frames)
    buffer.seek(0)
    return buffer.read()


def extract_message_from_audio(audio_bytes: bytes, password: str | None) -> str:
    with wave.open(io.BytesIO(audio_bytes)) as wav:
        if wav.getsampwidth() not in (1, 2):
            raise ValueError("Only 8-bit or 16-bit WAV files are supported.")
        params = wav.getparams()
        frames = wav.readframes(params.nframes)

    samples = len(frames) // params.sampwidth
    bits = []
    for sample_idx in range(samples):
        byte_index = sample_idx * params.sampwidth
        bits.append(frames[byte_index] & 1)

    if len(bits) < 32:
        raise ValueError("Audio payload is incomplete.")
    length = 0
    for bit in bits[:32]:
        length = (length << 1) | bit
    expected = (length + 4) * 8
    if expected > len(bits):
        raise ValueError("Audio payload is truncated.")
    payload_bits = bits[32:32 + length * 8]
    payload = _bits_to_bytes(payload_bits)
    return recover_message(payload, password)


def _bits_to_bytes(bits: list[int]) -> bytes:
    output = bytearray()
    for start in range(0, len(bits), 8):
        byte = 0
        for bit in bits[start:start + 8]:
            byte = (byte << 1) | bit
        if start + 8 <= len(bits):
            output.append(byte)
    return bytes(output)


def _html_page(title: str, body: str) -> str:
    return render_template_string(
        """<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>{{ title }}</title>
    <link rel='stylesheet' href='/style.css'>
</head>
<body class='result'>
    <div class='card'>
        <h1>{{ title }}</h1>
        {{ body|safe }}
        <p><a href='/'>Back to tool</a></p>
    </div>
</body>
</html>""",
        title=title,
        body=body,
    )


def _escape_for_input(value: str) -> str:
    escaped = html.escape(value, quote=True)
    return escaped.replace("\n", "&#10;").replace("\r", "&#13;")


def _format_message_block(message: str) -> str:
    safe = html.escape(message)
    return f"<pre class='message'>{safe}</pre>"


def _wants_json() -> bool:
    return request.headers.get("X-Requested-With") == "fetch"


@app.get("/")
def root() -> Response:
    return app.send_static_file("index.html")


@app.post("/encode-image")
def encode_image() -> Response:
    upload = request.files.get("image")
    message = request.form.get("message", "").strip()
    password = request.form.get("password") or None
    disable_compression = request.form.get("disable_compression") == "on"
    if not upload or not message:
        return _html_page("Encoding failed", "<p>Provide both an image and a message.</p>")
    raw = upload.read()
    if len(raw) > IMAGE_LIMIT:
        return _html_page("Encoding failed", "<p>Image exceeds the 5MB limit.</p>")
    filename = upload.filename or ""
    if "." not in filename:
        return _html_page("Encoding failed", "<p>Filename must include an extension.</p>")
    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in ("png", "jpg", "jpeg"):
        return _html_page("Encoding failed", "<p>Only PNG and JPG images are supported.</p>")
    fmt = "PNG" if ext == "png" else "JPEG"
    try:
        stego_bytes = hide_message_in_image(
            raw, message, password, fmt, compress=not disable_compression
        )
    except ValueError as exc:
        return _html_page("Encoding failed", f"<p>{exc}</p>")
    output = io.BytesIO(stego_bytes)
    output.seek(0)
    download_name = _steg_download_name(filename, ext)
    mimetype = "image/png" if fmt == "PNG" else "image/jpeg"
    return send_file(output, mimetype=mimetype, download_name=download_name, as_attachment=True)


@app.post("/decode-image")
def decode_image() -> Response:
    upload = request.files.get("image")
    password = request.form.get("password") or None
    if not upload:
        return _html_page("Decoding failed", "<p>Upload an image to continue.</p>")
    raw = upload.read()
    if len(raw) > IMAGE_LIMIT:
        return _html_page("Decoding failed", "<p>Image exceeds the 5MB limit.</p>")
    try:
        message = extract_message_from_image(raw, password)
    except ValueError as exc:
        return _html_page("Decoding failed", f"<p>{exc}</p>")
    download_form = (
        "<form method='post' action='/download-text'>"
        f"<input type='hidden' name='message' value='{_escape_for_input(message)}'>"
        "<button type='submit'>Download as .txt</button>"
        "</form>"
    )
    body = f"<p class='success'>Hidden message:</p>{_format_message_block(message)}{download_form}"
    return _html_page("Decoded message", body)


@app.post("/detect-image")
def detect_image() -> Response:
    upload = request.files.get("image")
    if not upload:
        if _wants_json():
            return jsonify({"ok": False, "message": "Upload an image to inspect."}), 400
        return _html_page("Detection failed", "<p>Upload an image to inspect.</p>")
    raw = upload.read()
    if len(raw) > IMAGE_LIMIT:
        if _wants_json():
            return jsonify({"ok": False, "message": "Image exceeds the 5MB limit."}), 400
        return _html_page("Detection failed", "<p>Image exceeds the 5MB limit.</p>")
    try:
        verdict = analyze_image_for_stego(raw)
    except ValueError as exc:
        if _wants_json():
            return jsonify({"ok": False, "message": str(exc)}), 400
        return _html_page("Detection failed", f"<p>{exc}</p>")
    if _wants_json():
        return jsonify({"ok": True, "message": verdict})
    body = f"<p>{verdict}</p>"
    return _html_page("Detection result", body)


@app.post("/encode-audio")
def encode_audio() -> Response:
    upload = request.files.get("audio")
    message = request.form.get("message", "").strip()
    password = request.form.get("password") or None
    disable_compression = request.form.get("disable_compression") == "on"
    if not upload or not message:
        return _html_page("Audio encoding failed", "<p>Provide both a WAV file and a message.</p>")
    raw = upload.read()
    if len(raw) > AUDIO_LIMIT:
        return _html_page("Audio encoding failed", "<p>Audio exceeds the 10MB limit.</p>")
    filename = upload.filename or ""
    if not filename.lower().endswith('.wav'):
        return _html_page("Audio encoding failed", "<p>Only .wav files are supported.</p>")
    try:
        output_bytes = embed_payload_in_audio(
            raw, message, password, compress=not disable_compression
        )
    except ValueError as exc:
        return _html_page("Audio encoding failed", f"<p>{exc}</p>")
    buffer = io.BytesIO(output_bytes)
    buffer.seek(0)
    base = filename.rsplit('.', 1)[0] if "." in filename else "audio"
    download = _steg_download_name(base, "wav")
    return send_file(buffer, mimetype="audio/wav", download_name=download, as_attachment=True)


@app.post("/decode-audio")
def decode_audio() -> Response:
    upload = request.files.get("audio")
    password = request.form.get("password") or None
    if not upload:
        return _html_page("Audio decoding failed", "<p>Upload a WAV file.</p>")
    raw = upload.read()
    if len(raw) > AUDIO_LIMIT:
        return _html_page("Audio decoding failed", "<p>Audio exceeds the 10MB limit.</p>")
    filename = upload.filename or ""
    if not filename.lower().endswith('.wav'):
        return _html_page("Audio decoding failed", "<p>Only .wav files are supported.</p>")
    try:
        message = extract_message_from_audio(raw, password)
    except ValueError as exc:
        return _html_page("Audio decoding failed", f"<p>{exc}</p>")
    download_form = (
        "<form method='post' action='/download-text'>"
        f"<input type='hidden' name='message' value='{_escape_for_input(message)}'>"
        "<button type='submit'>Download as .txt</button>"
        "</form>"
    )
    body = f"<p class='success'>Hidden message:</p>{_format_message_block(message)}{download_form}"
    return _html_page("Audio message", body)


@app.post("/download-text")
def download_text() -> Response:
    message = request.form.get("message", "")
    buffer = io.BytesIO(message.encode("utf-8"))
    buffer.seek(0)
    return send_file(buffer, mimetype="text/plain", download_name="decoded_message.txt", as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
