"""Visual rotor display for the Enigma theme (compact header mode)."""

import tkinter as tk
import math

ALPHABET_LIST = [chr(i) for i in range(ord('A'), ord('Z') + 1)]

class VisualEnigma:
    def __init__(self):
        self.rotor_colors = ["#ffb74d", "#64b5f6", "#e57373"]

    def draw_compact(self, canvas: tk.Canvas, positions: list):
        """Compact horizontal rotor display for header."""
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 50 or h < 50:
            return
        r = min(h, w // 3) // 2 - 10
        for i, pos in enumerate(positions):
            cx = (i * 2 + 1) * w // 6
            cy = h // 2
            canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                               outline=self.rotor_colors[i], width=2)
            for j in range(26):
                angle = math.radians((j - pos) * (360 / 26) + 90)
                x = cx + (r - 5) * math.cos(angle)
                y = cy - (r - 5) * math.sin(angle)
                canvas.create_text(x, y, text=ALPHABET_LIST[j],
                                   fill=self.rotor_colors[i], font=("Consolas", 6))
