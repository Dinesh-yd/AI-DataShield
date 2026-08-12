from io import BytesIO

from PIL import Image


def extract_text_from_image(data: bytes) -> str:
    try:
        import pytesseract
    except Exception:
        return ""

    try:
        image = Image.open(BytesIO(data))
        return pytesseract.image_to_string(image) or ""
    except Exception:
        return ""
