"""Generate PNG icons for the Chrome extension from SVG."""

import os
import sys

# Windows consoles default to cp1252, which can't print the check marks.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Shield SVG path - PhishPipeline logo
SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="24" fill="#1F4E79"/>
  <path d="M64 16 L100 30 V60 C100 88 82 108 64 116 C46 108 28 88 28 60 V30 Z"
        fill="#2E75B6"/>
  <path d="M48 64 L58 74 L80 52"
        stroke="white" stroke-width="7" stroke-linecap="round"
        stroke-linejoin="round" fill="none"/>
</svg>"""


def svg_to_png(svg_content, size, output_path):
    try:
        import cairosvg
        cairosvg.svg2png(
            bytestring=svg_content.encode(),
            write_to=output_path,
            output_width=size,
            output_height=size,
        )
        print(f"✓ Created {output_path} ({size}x{size})")
    except ImportError:
        # Fallback: create a minimal PNG programmatically
        _create_minimal_png(size, output_path)


def _create_minimal_png(size, output_path):
    """Create a simple colored square PNG without dependencies."""
    import struct
    import zlib

    def png_chunk(chunk_type, data):
        chunk_len = len(data)
        chunk = struct.pack('>I', chunk_len) + chunk_type + data
        crc = zlib.crc32(chunk_type + data) & 0xffffffff
        return chunk + struct.pack('>I', crc)

    # Create a simple navy blue square with white pixel pattern
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            # Navy background with a simple shield shape
            cx = size // 2
            # Simple shield outline
            if abs(x - cx) < size * 0.35 and size * 0.15 < y < size * 0.85:
                if y < size * 0.55:
                    row.extend([0x1F, 0x4E, 0x79])  # navy
                else:
                    # taper
                    taper = (y - size * 0.55) / (size * 0.30)
                    if abs(x - cx) < size * 0.35 * (1 - taper * 0.8):
                        row.extend([0x1F, 0x4E, 0x79])  # navy
                    else:
                        row.extend([0x0F, 0x1A, 0x27])  # dark
            else:
                row.extend([0x0F, 0x1A, 0x27])  # dark background
        pixels.append(bytes([0] + row))  # filter byte

    raw = zlib.compress(b''.join(pixels))

    png_data = (
        b'\x89PNG\r\n\x1a\n' +
        png_chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)) +
        png_chunk(b'IDAT', raw) +
        png_chunk(b'IEND', b'')
    )

    with open(output_path, 'wb') as f:
        f.write(png_data)
    print(f"✓ Created {output_path} ({size}x{size}) [fallback PNG]")


if __name__ == "__main__":
    os.makedirs("icons", exist_ok=True)
    for size in [16, 48, 128]:
        svg_to_png(SVG_CONTENT, size, f"icons/icon{size}.png")
    print("\nIcons created. Load the extension in Chrome:")
    print("  chrome://extensions → Developer Mode → Load unpacked")
