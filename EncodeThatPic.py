import sys
import base64
from PIL import Image

def encode_file_into_image(file_path, image_path):
    '''
    Encode the content of a file into layers 0 and 1 of a JPEG image.

    Args:
        file_path (str): The path to the file to be encoded.
        image_path (str): The path to the JPEG image file.
    '''
    with open(file_path, 'rb') as f:
        data = f.read()
    b64_data = base64.b64encode(data)
    encode_base64_into_image(b64_data, image_path)

def encode_base64_into_image(b64_data, image_path):
    '''
    Encode base64 data into layers 0 and 1 of a JPEG image.

    Args:
        b64_data (bytes): The base64-encoded data to be encoded into the image.
        image_path (str): The path to the JPEG image file.
    '''
    img = Image.open(image_path)
    img_data = img.tobytes()

    img_data = bytearray(img_data)
    for i in range(len(b64_data)):
        img_data[i] = (img_data[i] & 0xFE) | ((b64_data[i] >> 7) & 1)
        img_data[i+1] = (img_data[i+1] & 0xFE) | ((b64_data[i] >> 6) & 1)
        img_data[i+2] = (img_data[i+2] & 0xFE) | ((b64_data[i] >> 5) & 1)
        img_data[i+3] = (img_data[i+3] & 0xFE) | ((b64_data[i] >> 4) & 1)
        img_data[i+4] = (img_data[i+4] & 0xFE) | ((b64_data[i] >> 3) & 1)
        img_data[i+5] = (img_data[i+5] & 0xFE) | ((b64_data[i] >> 2) & 1)
        img_data[i+6] = (img_data[i+6] & 0xFE) | ((b64_data[i] >> 1) & 1)
        img_data[i+7] = (img_data[i+7] & 0xFE) | (b64_data[i] & 1)

    img_encoded = Image.frombytes(img.mode, img.size, bytes(img_data))
    img_encoded.save("encoded_image.jpg")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encode_image.py <file_path_or_base64_string> <image_path>")
        sys.exit(1)

    input_path = sys.argv[1]
    image_path = sys.argv[2]

    if input_path.startswith("data:"):
        b64_data = base64.b64decode(input_path.split(",")[1])
        encode_base64_into_image(b64_data, image_path)
    else:
        encode_file_into_image(input_path, image_path)

    print("Image encoded successfully!")
