"""Image dashboard panels: model rules, file-header checks and the upload body rule."""

import struct
import zlib
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Request
from pydantic import ValidationError

import keep.http as protocol
from keep.configuration.images import MAX_BYTES, InvalidImage, inspect
from keep.configuration.models import DashboardDefinition, ImagePanel, images_of, presets_of

IMAGE = "00000000-0000-4000-8000-000000000003"
PRESET = "00000000-0000-4000-8000-000000000002"


def panel(n, **fields):
    return {"id": f"00000000-0000-4000-8000-00000000001{n}", "x": 3 * n, "y": 0, "w": 3, "h": 2, **fields}


def png(width, height):
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr = struct.pack(">I", 13) + b"IHDR" + header + struct.pack(">I", zlib.crc32(b"IHDR" + header))
    return b"\x89PNG\r\n\x1a\n" + ihdr + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def gif(width, height):
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def jpeg(width, height):
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + b"\xff\xff" + sof + b"\xff\xd9"


def webp(chunk, payload):
    body = b"WEBP" + chunk + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", len(body)) + body


def webp_lossy(width, height):
    return webp(b"VP8 ", b"\x00" * 3 + b"\x9d\x01\x2a" + struct.pack("<HH", width, height) + b"\x00" * 4)


def webp_lossless(width, height):
    w, h = width - 1, height - 1
    bits = w | h << 14
    return webp(b"VP8L", b"\x2f" + struct.pack("<I", bits) + b"\x00" * 5)


def webp_extended(width, height):
    payload = b"\x00" * 4 + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return webp(b"VP8X", payload)


def test_image_panels_reference_no_preset_and_list_their_uploads():
    """Requirements: REV-62; dashboard operations 2 and 14."""
    board = DashboardDefinition(
        name="Board",
        panels=[
            panel(0, preset_id=PRESET),
            panel(1, type="image", image_id=IMAGE, alt="  Service map  "),
            panel(2, type="image", url="https://wiki.example.com/map.png", fit="cover"),
            panel(3, type="image", image_id=IMAGE, title="Again"),
        ],
    )
    upload, linked = board.panels[1], board.panels[2]
    assert isinstance(upload, ImagePanel) and upload.fit == "contain" and upload.alt == "Service map"
    assert linked.model_dump()["image_id"] is None and linked.fit == "cover"
    assert presets_of(board.panels) == [PRESET]
    assert images_of(board.panels) == [IMAGE]


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"image_id": IMAGE, "url": "https://example.com/a.png"},
        {"image_id": "0000000A-0000-4000-8000-00000000000B"},
        {"url": "http://example.com/a.png"},
        {"url": "javascript:alert(1)"},
        {"url": "https:///a.png"},
        {"url": "https://user:secret@example.com/a.png"},
        {"url": "https://user@example.com/a.png"},
        {"url": "https://example.com/a b.png"},
        {"url": "https://exämple.com/a.png"},
        {"url": "https://example.com:99999/a.png"},
        {"url": "https://example.com/" + "a" * 2048},
        {"image_id": IMAGE, "alt": "a" * 301},
        {"image_id": IMAGE, "alt": "two\nlines"},
        {"image_id": IMAGE, "fit": "stretch"},
        {"image_id": IMAGE, "preset_id": PRESET},
        {"image_id": IMAGE, "html": "<p>x</p>"},
    ],
)
def test_image_panels_reject_bad_sources_and_settings(fields):
    """Requirements: REV-62; dashboard operations 14."""
    with pytest.raises(ValidationError):
        DashboardDefinition(name="Board", panels=[panel(0, type="image", **fields)])


def test_blank_descriptions_are_dropped():
    """Requirements: REV-62; dashboard operations 16."""
    assert ImagePanel.model_validate(panel(0, type="image", image_id=IMAGE, alt="   ")).alt is None


@pytest.mark.parametrize(
    ("data", "found"),
    [
        (png(1600, 900), ("image/png", 1600, 900)),
        (gif(320, 200), ("image/gif", 320, 200)),
        (jpeg(1024, 768), ("image/jpeg", 1024, 768)),
        (webp_lossy(640, 480), ("image/webp", 640, 480)),
        (webp_lossless(800, 450), ("image/webp", 800, 450)),
        (webp_extended(8000, 1), ("image/webp", 8000, 1)),
    ],
    ids=["png", "gif", "jpeg", "webp-lossy", "webp-lossless", "webp-extended"],
)
def test_headers_give_the_real_type_and_size(data, found):
    """Requirements: REV-62 file checks."""
    assert inspect(data) == found


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b'<svg xmlns="http://www.w3.org/2000/svg"></svg>',
        b"<html><script>alert(1)</script></html>",
        b"BM" + b"\x00" * 60,
        png(8001, 10),
        png(10, 0),
        jpeg(9000, 10),
        gif(0, 5),
        png(10, 10)[:20],
        b"\xff\xd8\xff\xe0\x00\x01",
        webp_lossy(10, 10)[:-6] + b"\x00",
        webp(b"ALPH", b"\x00" * 20),
        png(10, 10) + b"\x00" * (MAX_BYTES + 1),
    ],
    ids=lambda data: f"{data[:8].hex()}-{len(data)}",
)
def test_other_files_are_rejected(data):
    """Requirements: REV-62 limits and file checks."""
    with pytest.raises(InvalidImage):
        inspect(data)


def application():
    app = protocol.create_http_app(None)
    app.state.settings = SimpleNamespace(
        environment="development", role="product-api", clock_health_file=None
    )
    seen = []

    @app.post("/api/tenants/{tenant}/dashboard-images")
    @app.post("/api/tenants/{tenant}/dashboards")
    async def handler(request: Request):
        seen.append((await request.body(), getattr(request.state, "json_body", "absent")))
        return {"ok": True}

    return app, seen


async def send(app, path, content, media):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://upload.test"
    ) as client:
        return await client.post(path, content=content, headers={"content-type": media})


@pytest.mark.asyncio
async def test_upload_route_takes_a_raw_image_body_up_to_5_mib():
    """Requirements: REV-62; dashboard operations 14."""
    app, seen = application()
    data = png(10, 10)
    response = await send(app, "/api/tenants/t/dashboard-images", data, "image/png")
    assert response.status_code == 200 and seen == [(data, "absent")]
    for media in ("image/svg+xml", "application/json", "text/plain"):
        response = await send(app, "/api/tenants/t/dashboard-images", b"{}", media)
        assert response.status_code == 415
    response = await send(app, "/api/tenants/t/dashboard-images", b"x" * (MAX_BYTES + 1), "image/gif")
    assert response.status_code == 413
    # Every other product route still takes JSON only, within its own limit.
    response = await send(app, "/api/tenants/t/dashboards", data, "image/png")
    assert response.status_code == 415
    response = await send(app, "/api/tenants/t/dashboards", b"{" + b" " * 70000 + b"}", "application/json")
    assert response.status_code == 413


def test_only_served_images_revalidate_instead_of_skipping_the_cache():
    """Requirements: REV-62; dashboard operations 14."""
    assert protocol.is_image_read("/api/tenants/abc/dashboard-images/def")
    for path in (
        "/api/tenants/abc/dashboard-images",
        "/api/tenants/abc/dashboards/def",
        "/api/tenants/abc/dashboard-images/def/x",
    ):
        assert not protocol.is_image_read(path)


def test_only_the_collection_path_is_the_upload_route():
    """Requirements: REV-62; dashboard operations 14."""
    assert protocol.is_image_upload("/api/tenants/abc/dashboard-images")
    for path in (
        "/api/tenants/abc/dashboard-images/x",
        "/api/tenants/abc/dashboards",
        "/api/admin/abc/dashboard-images",
        "/api/tenants/dashboard-images",
    ):
        assert not protocol.is_image_upload(path)
