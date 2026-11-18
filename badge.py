from typing import Any, Optional

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


def _estimate_text_width(text: str) -> int:
    return max(int(len(str(text)) * 6.5) + 12, 20)


def generate_badge_svg(label: str = "TrustAudit", score: Any = "UNKNOWN", grade: Optional[str] = None) -> str:
    """
    Generates a Shields.io standard SVG badge.
    Accepts string status ('GREEN', 'YELLOW', 'RED') or numeric score (0-100).
    """
    if isinstance(score, (int, float)):
        num = int(score)
        gr = grade or ("A" if num >= 90 else ("B" if num >= 80 else ("C" if num >= 70 else "F")))
        message = f"{num}/100 {gr}"
        if num >= 90:
            color = "#22c55e"
        elif num >= 80:
            color = "#3b82f6"
        elif num >= 70:
            color = "#eab308"
        else:
            color = "#ef4444"
    else:
        score_str = str(score).upper()
        message = SCORE_LABELS.get(score_str, score_str.lower() if score_str != "UNKNOWN" else "unknown")
        color = SCORE_COLORS.get(score_str, SCORE_COLORS["UNKNOWN"])

    label_width = _estimate_text_width(label)
    message_width = _estimate_text_width(message)
    total_width = label_width + message_width

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {message}">
<linearGradient id="b" x2="0" y2="100%">
<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<mask id="a">
<rect width="{total_width}" height="20" rx="3" fill="#fff"/>
</mask>
<g mask="url(#a)">
<rect width="{label_width}" height="20" fill="#24292e"/>
<rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
<rect width="{total_width}" height="20" fill="url(#b)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" font-weight="600" font-size="11">
<text x="{label_width / 2}" y="14">{label}</text>
<text x="{label_width + message_width / 2}" y="14">{message}</text>
</g>
</svg>'''
    return svg
