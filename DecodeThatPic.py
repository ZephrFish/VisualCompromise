import sys
import base64
from PIL import Image

def decode_image(image_path):
    '''
    Decode the base64 data from layers 0 and 1 of a JPEG image.

    Args:
        image_path (str): The path to the JPEG image file.

    Returns:
        bytes: The decoded data.
    '''
    img = Image.open(image_path)
    img_data = img.tobytes()

    binary_data = ""
    for byte in img_data:
        # Extract the LSB (Least Significant Bit) from each byte
        lsb = byte & 1
        # Convert the LSB to a binary string and append to the binary data
        binary_data += str(lsb)

    try:
        # Pad the binary data to a multiple of 8
        padding = len(binary_data) % 8
        if padding:
            binary_data = binary_data[:-padding]
        # Convert binary data to bytes and decode using base64
        decoded_data = base64.b64decode(bytes([int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8)]))
    except (ValueError, IndexError) as e:
        print("Error decoding data:", e)
        sys.exit(1)

    return decoded_data

def save_decoded_data(decoded_data, output_file):
    '''
    Save the decoded data to a file.

    Args:
        decoded_data (bytes): The decoded data.
        output_file (str): The path to the output file.
    '''
    with open(output_file, 'wb') as f:
        f.write(decoded_data)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decode_image.py <image_path> <output_file>")
        sys.exit(1)

    image_path = sys.argv[1]
    output_file = sys.argv[2]

    decoded_data = decode_image(image_path)
    save_decoded_data(decoded_data, output_file)

    print("Data decoded and saved successfully!")
