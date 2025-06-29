from PIL import Image
from PIL.ExifTags import TAGS

def extract_metadata(image_path):
    try:
        img = Image.open(image_path)
        exif_data = img._getexif()
        if not exif_data:
            return {"result": "No EXIF metadata found."}
        return {TAGS.get(k, k): v for k, v in exif_data.items()}
    except Exception as e:
        return {"error": str(e)}

# Example usage:
# print(extract_metadata("test.jpg"))