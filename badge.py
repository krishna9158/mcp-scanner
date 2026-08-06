SCORE_COLORS = {
    "GREEN": "#4c1",
    "YELLOW": "#dfb317",
    "RED": "#e05d44",
    "UNKNOWN": "#9f9f9f",
}

SCORE_LABELS = {
    "GREEN": "passing",
    "YELLOW": "warnings",
    "RED": "failing",
    "UNKNOWN": "not scanned",
}


def _estimate_text_width(text):
    # Rough width estimate (~6.5px per character at this font size) - not
    # pixel-perfect, but good enough for a simple, functional badge without
    # needing a real font-rendering library.
    return max(int(len(text) * 6.5) + 10, 20)


def generate_badge_svg(label="MCP Security", score="UNKNOWN"):
    message = SCORE_LABELS.get(score, "unknown")
    color = SCORE_COLORS.get(score, SCORE_COLORS["UNKNOWN"])

    label_width = _estimate_text_width(label)
    message_width = _estimate_text_width(message)
    total_width = label_width + message_width

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
<linearGradient id="b" x2="0" y2="100%">
<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<mask id="a">
<rect width="{total_width}" height="20" rx="3" fill="#fff"/>
</mask>
<g mask="url(#a)">
<rect width="{label_width}" height="20" fill="#555"/>
<rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
<rect width="{total_width}" height="20" fill="url(#b)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
<text x="{label_width / 2}" y="14">{label}</text>
<text x="{label_width + message_width / 2}" y="14">{message}</text>
</g>
</svg>'''
    return svg
