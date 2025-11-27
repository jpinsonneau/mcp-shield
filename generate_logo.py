#!/usr/bin/env python3
"""
Generate MCP Shield logo as PNG
"""

from PIL import Image, ImageDraw, ImageFont
import math

# Create image with transparent background
width, height = 800, 600
img = Image.new('RGBA', (width, height), (255, 255, 255, 0))
draw = ImageDraw.Draw(img)

# Color scheme - professional blue and silver
shield_color = (30, 58, 138)  # Dark blue
shield_border = (15, 23, 42)   # Darker blue for border
text_color = (255, 255, 255)   # White
accent_color = (59, 130, 246)  # Bright blue accent

# Draw shield shape (classic heraldic shield)
def draw_shield(draw, center_x, center_y, width, height):
    """Draw a classic shield shape"""
    points = [
        (center_x, center_y - height // 2),  # Top point
        (center_x - width // 2, center_y - height // 4),  # Top left
        (center_x - width // 2, center_y + height // 4),  # Bottom left
        (center_x - width // 3, center_y + height // 2),  # Bottom left curve
        (center_x, center_y + height // 2 - 10),  # Bottom point
        (center_x + width // 3, center_y + height // 2),  # Bottom right curve
        (center_x + width // 2, center_y + height // 4),  # Bottom right
        (center_x + width // 2, center_y - height // 4),  # Top right
    ]
    
    # Draw shield with border
    draw.polygon(points, fill=shield_color, outline=shield_border, width=8)
    
    # Add inner highlight for depth
    highlight_points = [
        (center_x, center_y - height // 2 + 20),
        (center_x - width // 2 + 15, center_y - height // 4 + 10),
        (center_x - width // 2 + 15, center_y + height // 4 - 10),
        (center_x - width // 3 + 10, center_y + height // 2 - 20),
        (center_x, center_y + height // 2 - 30),
        (center_x + width // 3 - 10, center_y + height // 2 - 20),
        (center_x + width // 2 - 15, center_y + height // 4 - 10),
        (center_x + width // 2 - 15, center_y - height // 4 + 10),
    ]
    draw.polygon(highlight_points, fill=(59, 130, 246, 100), outline=None)

# Draw the shield
shield_center_x = width // 2
shield_center_y = height // 2 - 20
shield_width = 400
shield_height = 450
draw_shield(draw, shield_center_x, shield_center_y, shield_width, shield_height)

# Try to use a nice font, fallback to default if not available
try:
    # Try to use a bold font
    title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
    subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
except:
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSans-Bold.ttf", 72)
        subtitle_font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSans-Bold.ttf", 48)
    except:
        # Fallback to default font
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()

# Draw "MCP" text on top of shield
mcp_text = "MCP"
bbox = draw.textbbox((0, 0), mcp_text, font=title_font)
mcp_text_width = bbox[2] - bbox[0]
mcp_text_height = bbox[3] - bbox[1]
mcp_x = shield_center_x - mcp_text_width // 2
mcp_y = shield_center_y - 80
draw.text((mcp_x, mcp_y), mcp_text, fill=text_color, font=title_font)

# Draw "SHIELD" text below MCP
shield_text = "SHIELD"
bbox = draw.textbbox((0, 0), shield_text, font=subtitle_font)
shield_text_width = bbox[2] - bbox[0]
shield_text_height = bbox[3] - bbox[1]
shield_x = shield_center_x - shield_text_width // 2
shield_y = shield_center_y + 20
draw.text((shield_x, shield_y), shield_text, fill=text_color, font=subtitle_font)

# Save the image
img.save('logo.png', 'PNG')
print("Logo generated: logo.png")

