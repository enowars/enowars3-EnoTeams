from PIL import Image, ImageFont, ImageDraw
import secrets
import string
import io


def _draw_lines(draw_context, width, height, amount=100, max_length=80, max_width=4):
    for _ in range(amount):
        start = (secrets.randbelow(width), secrets.randbelow(height))

        draw_context.line([start, (start[0] + secrets.randbelow(max_length) - max_length / 2,
                                   start[1] + secrets.randbelow(max_length) - max_length / 2)],
                          "#000000", width=secrets.randbelow(max_width))


def _draw_dots(draw_context, width, height, amount=60, max_radius=8):
    for _ in range(amount):
        mid = (secrets.randbelow(width), secrets.randbelow(height))

        draw_context.ellipse([mid[0] - secrets.randbelow(max_radius), mid[1] - secrets.randbelow(max_radius),
                              mid[0] + secrets.randbelow(max_radius), mid[1] + secrets.randbelow(max_radius)],
                             fill="#000000")


def generate_captcha(text=None, image_width=400, image_height=200, font_height=40, vertical_change_max=80):
    """
    Generates a black and white image containing the given text and some lines and ellipses.
    The image width should suit to the text length and font height.
    :param text: upper case text to be drawn or None to generate some
    :param image_width: optional width of the resulting image
    :param image_height: optional height of the resulting image
    :param font_height: optional height of the characters
    :param vertical_change_max: optional max height difference between characters
    :return: tuple of the text and the resulting image as a .png inside a BytesIO buffer
    """

    if text is None:
        text = ""
        for _ in range(8):
            text += secrets.choice(string.ascii_uppercase)
    else:
        text = text.upper()

    fnt = ImageFont.truetype("Lobster.ttf", font_height)
    text_width = fnt.getsize(text)[0]

    if text_width > image_width - 20:
        print("Text width exceeds image width.")

    image = Image.new("RGB", (image_width, image_height), "#ffffff")
    draw_context = ImageDraw.Draw(image)

    _draw_lines(draw_context, image_width, image_height)
    _draw_dots(draw_context, image_width, image_height)

    equal_padding = int((image_width - 20 - text_width) / (len(text) + 1))
    horizontal_change = max(20, equal_padding)

    current_width = equal_padding + 10
    current_height = 10 + secrets.randbelow(image_height - 10 - font_height)
    for char in text:
        draw_context.text(
            (current_width + (secrets.randbelow(horizontal_change) - horizontal_change / 2), current_height), char,
            font=fnt, fill="#000000")

        current_width += fnt.getsize(char)[0] + equal_padding
        current_height = min(
            max(current_height + (secrets.randbelow(vertical_change_max) - vertical_change_max / 2), 10),
            image_height - 10 - font_height)

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    return text, buffer
