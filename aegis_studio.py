#!/usr/bin/env python3
# Copyright (c) 2024-2026 Jorge Francisco Paredes (irstabyjorge)
# AEGIS Studio — Multimedia Hub: Download, Edit, Play, Record, Convert
# Image editor, video player/editor, audio recorder, 3D effects, URL downloader.

__version__ = "1.0.0"

import sys, os, json, subprocess, threading, shutil, re, time
from pathlib import Path
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, colorchooser, font as tkfont, scrolledtext
except ImportError:
    print("tkinter required"); sys.exit(1)

try:
    from PIL import Image, ImageTk, ImageFilter, ImageEnhance, ImageDraw, ImageFont, ImageOps
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

STUDIO_DIR = Path.home() / "aegis_omni_xeon" / "studio"
DOWNLOADS = STUDIO_DIR / "downloads"
PROJECTS = STUDIO_DIR / "projects"
RECORDINGS = STUDIO_DIR / "recordings"
EXPORTS = STUDIO_DIR / "exports"
for d in [STUDIO_DIR, DOWNLOADS, PROJECTS, RECORDINGS, EXPORTS]:
    d.mkdir(parents=True, exist_ok=True)

BG = "#0a0a0a"
BG2 = "#111111"
BG3 = "#1a1a1a"
ACCENT = "#00ff88"
ACCENT2 = "#00cc66"
TEXT = "#cccccc"
TEXT_DIM = "#555555"
BORDER = "#2a2a2a"
RED = "#ff4444"
BLUE = "#4488ff"
YELLOW = "#ffaa00"


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _has(cmd):
    return shutil.which(cmd) is not None


# ─── Downloader Tab ─────────────────────────────────────────────────────────

class DownloaderTab(tk.Frame):
    def __init__(self, parent, log_fn):
        super().__init__(parent, bg=BG)
        self.log = log_fn
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG2, padx=15, pady=10)
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(top, text="DOWNLOADER", font=("Consolas", 14, "bold"),
                 fg=ACCENT, bg=BG2).pack(anchor="w")
        tk.Label(top, text="Download videos, websites, files, executables — anything from a URL",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG2).pack(anchor="w", pady=(2, 8))

        # URL input
        url_frame = tk.Frame(top, bg=BG2)
        url_frame.pack(fill=tk.X, pady=4)
        tk.Label(url_frame, text="URL:", fg=TEXT, bg=BG2, font=("Consolas", 10), width=8, anchor="w").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        tk.Entry(url_frame, textvariable=self.url_var, bg=BG3, fg=TEXT, insertbackground=ACCENT,
                 font=("Consolas", 11), relief=tk.FLAT, borderwidth=6).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Type selector
        type_frame = tk.Frame(top, bg=BG2)
        type_frame.pack(fill=tk.X, pady=4)
        tk.Label(type_frame, text="Type:", fg=TEXT, bg=BG2, font=("Consolas", 10), width=8, anchor="w").pack(side=tk.LEFT)
        self.type_var = tk.StringVar(value="auto")
        for val, label in [("auto", "Auto-detect"), ("video", "Video (yt-dlp)"),
                           ("website", "Clone Website"), ("file", "Direct File")]:
            tk.Radiobutton(type_frame, text=label, variable=self.type_var, value=val,
                           fg=TEXT, bg=BG2, selectcolor=BG3, activebackground=BG2,
                           activeforeground=ACCENT, font=("Consolas", 9)).pack(side=tk.LEFT, padx=6)

        # Output dir
        dir_frame = tk.Frame(top, bg=BG2)
        dir_frame.pack(fill=tk.X, pady=4)
        tk.Label(dir_frame, text="Save to:", fg=TEXT, bg=BG2, font=("Consolas", 10), width=8, anchor="w").pack(side=tk.LEFT)
        self.dir_var = tk.StringVar(value=str(DOWNLOADS))
        tk.Entry(dir_frame, textvariable=self.dir_var, bg=BG3, fg=TEXT_DIM,
                 font=("Consolas", 9), relief=tk.FLAT, borderwidth=4).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(dir_frame, text="Browse", command=self._browse_dir,
                  bg=BG3, fg=TEXT, font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=4)

        # Buttons
        btn_frame = tk.Frame(top, bg=BG2)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        tk.Button(btn_frame, text="  DOWNLOAD  ", command=self._download,
                  bg=ACCENT, fg="#000", font=("Consolas", 11, "bold"), relief=tk.FLAT,
                  padx=20, cursor="hand2").pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Open Folder", command=self._open_folder,
                  bg=BG3, fg=TEXT, font=("Consolas", 10), relief=tk.FLAT, padx=12).pack(side=tk.LEFT, padx=8)

        # Output log
        self.output = scrolledtext.ScrolledText(self, bg=BG2, fg=TEXT, font=("Consolas", 9),
                                                 relief=tk.FLAT, height=14, state=tk.DISABLED)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _browse_dir(self):
        d = filedialog.askdirectory(initialdir=self.dir_var.get())
        if d:
            self.dir_var.set(d)

    def _open_folder(self):
        subprocess.Popen(["xdg-open", self.dir_var.get()])

    def _log_output(self, text):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def _download(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("No URL", "Enter a URL to download.")
            return
        dtype = self.type_var.get()
        outdir = self.dir_var.get()

        self._log_output(f"\n--- Downloading: {url} ---")
        self._log_output(f"Type: {dtype}  Output: {outdir}")
        threading.Thread(target=self._do_download, args=(url, dtype, outdir), daemon=True).start()

    def _do_download(self, url, dtype, outdir):
        if dtype == "auto":
            if any(h in url for h in ["youtube.com", "youtu.be", "vimeo.com", "tiktok.com",
                                       "instagram.com", "twitter.com", "x.com", "twitch.tv",
                                       "dailymotion.com", "reddit.com"]):
                dtype = "video"
            elif url.endswith((".exe", ".dmg", ".zip", ".tar.gz", ".deb", ".AppImage", ".rpm",
                               ".iso", ".img", ".bin", ".msi", ".pkg")):
                dtype = "file"
            else:
                dtype = "file"

        if dtype == "video":
            if not _has("yt-dlp"):
                self._safe_log("yt-dlp not found. Install with: pip install yt-dlp")
                return
            cmd = f'yt-dlp -o "{outdir}/%(title)s.%(ext)s" --no-playlist "{url}"'
            self._safe_log(f"Running: yt-dlp ...")
            code, out, err = _run(cmd, timeout=600)
            self._safe_log(out if out else err)
            if code == 0:
                self._safe_log("Download complete!")
            else:
                self._safe_log(f"Error (code {code})")

        elif dtype == "website":
            if not _has("wget"):
                self._safe_log("wget not found")
                return
            domain = re.sub(r'https?://', '', url).split('/')[0]
            site_dir = f"{outdir}/{domain}"
            cmd = f'wget --mirror --convert-links --adjust-extension --page-requisites --no-parent -P "{site_dir}" "{url}" 2>&1 | tail -20'
            self._safe_log(f"Cloning website to {site_dir} ...")
            code, out, err = _run(cmd, timeout=300)
            self._safe_log(out or err or "Done")

        elif dtype == "file":
            filename = url.split("/")[-1].split("?")[0] or "download"
            filepath = f"{outdir}/{filename}"
            cmd = f'curl -L -o "{filepath}" --progress-bar "{url}" 2>&1'
            self._safe_log(f"Downloading to {filepath} ...")
            code, out, err = _run(cmd, timeout=600)
            if code == 0:
                size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
                self._safe_log(f"Saved: {filepath} ({size / 1024 / 1024:.1f} MB)")
            else:
                self._safe_log(f"Error: {err}")

    def _safe_log(self, text):
        self.after(0, self._log_output, text)


# ─── Image Editor Tab ───────────────────────────────────────────────────────

class ImageEditorTab(tk.Frame):
    def __init__(self, parent, log_fn):
        super().__init__(parent, bg=BG)
        self.log = log_fn
        self.current_image = None
        self.original_image = None
        self.photo = None
        self.draw_color = "#00ff88"
        self.draw_size = 3
        self.drawing = False
        self.last_x = 0
        self.last_y = 0
        self.tool = "brush"
        self._build()

    def _build(self):
        # Toolbar
        toolbar = tk.Frame(self, bg=BG2, padx=8, pady=6)
        toolbar.pack(fill=tk.X, padx=10, pady=(10, 0))

        tk.Label(toolbar, text="IMAGE EDITOR", font=("Consolas", 12, "bold"),
                 fg=ACCENT, bg=BG2).pack(side=tk.LEFT, padx=(0, 15))

        for text, cmd in [("Open", self._open_image), ("Save", self._save_image), ("Save As", self._save_as)]:
            tk.Button(toolbar, text=text, command=cmd, bg=BG3, fg=TEXT,
                      font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        # Drawing tools
        self.tool_var = tk.StringVar(value="brush")
        for val, label in [("brush", "Brush"), ("line", "Line"), ("rect", "Rect"),
                           ("circle", "Circle"), ("text", "Text"), ("eraser", "Eraser")]:
            tk.Radiobutton(toolbar, text=label, variable=self.tool_var, value=val,
                           fg=TEXT, bg=BG2, selectcolor=BG3, activebackground=BG2,
                           font=("Consolas", 9), indicatoron=0, padx=6, pady=2).pack(side=tk.LEFT, padx=1)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        tk.Button(toolbar, text="Color", command=self._pick_color, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=6).pack(side=tk.LEFT, padx=2)

        self.color_preview = tk.Canvas(toolbar, width=20, height=20, bg=self.draw_color, highlightthickness=1,
                                        highlightbackground=BORDER)
        self.color_preview.pack(side=tk.LEFT, padx=4)

        tk.Label(toolbar, text="Size:", fg=TEXT_DIM, bg=BG2, font=("Consolas", 9)).pack(side=tk.LEFT, padx=(8, 2))
        self.size_var = tk.IntVar(value=3)
        tk.Spinbox(toolbar, from_=1, to=50, textvariable=self.size_var, width=4,
                   bg=BG3, fg=TEXT, font=("Consolas", 9), buttonbackground=BG3).pack(side=tk.LEFT)

        # Filters toolbar
        filter_bar = tk.Frame(self, bg=BG2, padx=8, pady=4)
        filter_bar.pack(fill=tk.X, padx=10, pady=(2, 0))

        tk.Label(filter_bar, text="Filters:", fg=TEXT_DIM, bg=BG2, font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 6))
        for text, cmd in [("Blur", lambda: self._apply_filter("blur")),
                          ("Sharpen", lambda: self._apply_filter("sharpen")),
                          ("Edges", lambda: self._apply_filter("edges")),
                          ("Emboss", lambda: self._apply_filter("emboss")),
                          ("B&W", lambda: self._apply_filter("bw")),
                          ("Invert", lambda: self._apply_filter("invert")),
                          ("Sepia", lambda: self._apply_filter("sepia")),
                          ("Contrast+", lambda: self._apply_enhance("contrast", 1.5)),
                          ("Bright+", lambda: self._apply_enhance("brightness", 1.3)),
                          ("Rotate 90", self._rotate),
                          ("Flip H", lambda: self._flip("h")),
                          ("Flip V", lambda: self._flip("v")),
                          ("Resize", self._resize_dialog),
                          ("Crop", self._crop_mode),
                          ("Undo", self._undo)]:
            tk.Button(filter_bar, text=text, command=cmd, bg=BG3, fg=TEXT,
                      font=("Consolas", 8), relief=tk.FLAT, padx=5, pady=1).pack(side=tk.LEFT, padx=1)

        # Canvas
        canvas_frame = tk.Frame(self, bg=BG)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.canvas = tk.Canvas(canvas_frame, bg="#1a1a1a", highlightthickness=0, cursor="crosshair")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<ButtonPress-1>", self._mouse_down)
        self.canvas.bind("<B1-Motion>", self._mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self._mouse_up)

        # Status
        self.status = tk.Label(self, text="No image loaded — click Open to start",
                               fg=TEXT_DIM, bg=BG, font=("Consolas", 9), anchor="w")
        self.status.pack(fill=tk.X, padx=12, pady=(0, 6))

    def _open_image(self):
        if not HAS_PIL:
            messagebox.showerror("Error", "Pillow not installed")
            return
        path = filedialog.askopenfilename(filetypes=[
            ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.webp *.svg"),
            ("All files", "*.*")])
        if path:
            self.current_image = Image.open(path).convert("RGBA")
            self.original_image = self.current_image.copy()
            self._filepath = path
            self._display()
            self.status.config(text=f"{Path(path).name} — {self.current_image.size[0]}x{self.current_image.size[1]}")

    def _display(self):
        if not self.current_image:
            return
        cw = self.canvas.winfo_width() or 800
        ch = self.canvas.winfo_height() or 500
        img = self.current_image.copy()
        img.thumbnail((cw, ch), Image.LANCZOS)
        self.photo = ImageTk.PhotoImage(img)
        self.canvas.delete("all")
        self.canvas.create_image(cw // 2, ch // 2, image=self.photo, anchor="center")
        self._display_img = img

    def _save_image(self):
        if self.current_image and hasattr(self, '_filepath'):
            out = self._filepath
            if out.lower().endswith(('.jpg', '.jpeg')):
                self.current_image.convert("RGB").save(out)
            else:
                self.current_image.save(out)
            self.status.config(text=f"Saved: {out}")

    def _save_as(self):
        if not self.current_image:
            return
        path = filedialog.asksaveasfilename(defaultextension=".png",
                                             filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg"),
                                                        ("BMP", "*.bmp"), ("WEBP", "*.webp")])
        if path:
            if path.lower().endswith(('.jpg', '.jpeg')):
                self.current_image.convert("RGB").save(path)
            else:
                self.current_image.save(path)
            self._filepath = path
            self.status.config(text=f"Saved: {path}")

    def _apply_filter(self, name):
        if not self.current_image:
            return
        self.original_image = self.current_image.copy()
        img = self.current_image
        if name == "blur":
            self.current_image = img.filter(ImageFilter.GaussianBlur(3))
        elif name == "sharpen":
            self.current_image = img.filter(ImageFilter.SHARPEN)
        elif name == "edges":
            self.current_image = img.filter(ImageFilter.FIND_EDGES)
        elif name == "emboss":
            self.current_image = img.filter(ImageFilter.EMBOSS)
        elif name == "bw":
            self.current_image = img.convert("L").convert("RGBA")
        elif name == "invert":
            r, g, b, a = img.split()
            self.current_image = Image.merge("RGBA", (ImageOps.invert(r), ImageOps.invert(g), ImageOps.invert(b), a))
        elif name == "sepia":
            gray = img.convert("L")
            sepia = Image.merge("RGB", (
                gray.point(lambda x: min(255, int(x * 1.2))),
                gray.point(lambda x: int(x * 1.0)),
                gray.point(lambda x: int(x * 0.8)),
            ))
            self.current_image = sepia.convert("RGBA")
        self._display()

    def _apply_enhance(self, kind, factor):
        if not self.current_image:
            return
        self.original_image = self.current_image.copy()
        rgb = self.current_image.convert("RGB")
        if kind == "contrast":
            rgb = ImageEnhance.Contrast(rgb).enhance(factor)
        elif kind == "brightness":
            rgb = ImageEnhance.Brightness(rgb).enhance(factor)
        self.current_image = rgb.convert("RGBA")
        self._display()

    def _rotate(self):
        if self.current_image:
            self.original_image = self.current_image.copy()
            self.current_image = self.current_image.rotate(-90, expand=True)
            self._display()

    def _flip(self, direction):
        if self.current_image:
            self.original_image = self.current_image.copy()
            if direction == "h":
                self.current_image = ImageOps.mirror(self.current_image)
            else:
                self.current_image = ImageOps.flip(self.current_image)
            self._display()

    def _resize_dialog(self):
        if not self.current_image:
            return
        dlg = tk.Toplevel(self)
        dlg.title("Resize Image")
        dlg.geometry("300x150")
        dlg.configure(bg=BG2)
        w, h = self.current_image.size
        tk.Label(dlg, text=f"Current: {w}x{h}", fg=TEXT, bg=BG2, font=("Consolas", 10)).pack(pady=8)
        f = tk.Frame(dlg, bg=BG2)
        f.pack()
        tk.Label(f, text="W:", fg=TEXT, bg=BG2).pack(side=tk.LEFT)
        wvar = tk.IntVar(value=w)
        tk.Entry(f, textvariable=wvar, width=6, bg=BG3, fg=TEXT, font=("Consolas", 10)).pack(side=tk.LEFT, padx=4)
        tk.Label(f, text="H:", fg=TEXT, bg=BG2).pack(side=tk.LEFT)
        hvar = tk.IntVar(value=h)
        tk.Entry(f, textvariable=hvar, width=6, bg=BG3, fg=TEXT, font=("Consolas", 10)).pack(side=tk.LEFT, padx=4)

        def do_resize():
            self.original_image = self.current_image.copy()
            self.current_image = self.current_image.resize((wvar.get(), hvar.get()), Image.LANCZOS)
            self._display()
            self.status.config(text=f"Resized to {wvar.get()}x{hvar.get()}")
            dlg.destroy()
        tk.Button(dlg, text="Resize", command=do_resize, bg=ACCENT, fg="#000",
                  font=("Consolas", 10, "bold"), relief=tk.FLAT, padx=15).pack(pady=12)

    def _crop_mode(self):
        if self.current_image:
            self.status.config(text="Crop: draw a rectangle on the image, then release")
            self.tool_var.set("crop")

    def _undo(self):
        if self.original_image:
            self.current_image = self.original_image.copy()
            self._display()

    def _pick_color(self):
        color = colorchooser.askcolor(initialcolor=self.draw_color)
        if color[1]:
            self.draw_color = color[1]
            self.color_preview.config(bg=self.draw_color)

    def _mouse_down(self, e):
        self.drawing = True
        self.last_x = e.x
        self.last_y = e.y
        self.draw_size = self.size_var.get()
        self.tool = self.tool_var.get()

    def _mouse_drag(self, e):
        if not self.drawing or not self.current_image:
            return
        if self.tool in ("brush", "eraser"):
            color = self.draw_color if self.tool == "brush" else "#000000"
            self.canvas.create_line(self.last_x, self.last_y, e.x, e.y,
                                    fill=color, width=self.draw_size, capstyle=tk.ROUND)
            draw = ImageDraw.Draw(self.current_image)
            scale_x = self.current_image.size[0] / (self._display_img.size[0] if hasattr(self, '_display_img') else self.current_image.size[0])
            scale_y = self.current_image.size[1] / (self._display_img.size[1] if hasattr(self, '_display_img') else self.current_image.size[1])
            draw.line([(self.last_x * scale_x, self.last_y * scale_y),
                       (e.x * scale_x, e.y * scale_y)],
                      fill=color, width=max(1, int(self.draw_size * scale_x)))
        elif self.tool == "rect":
            self.canvas.delete("preview")
            self.canvas.create_rectangle(self.last_x, self.last_y, e.x, e.y,
                                          outline=self.draw_color, width=self.draw_size, tags="preview")
        elif self.tool == "circle":
            self.canvas.delete("preview")
            self.canvas.create_oval(self.last_x, self.last_y, e.x, e.y,
                                     outline=self.draw_color, width=self.draw_size, tags="preview")
        elif self.tool == "crop":
            self.canvas.delete("preview")
            self.canvas.create_rectangle(self.last_x, self.last_y, e.x, e.y,
                                          outline=YELLOW, width=2, dash=(4, 4), tags="preview")

        if self.tool in ("brush", "eraser"):
            self.last_x = e.x
            self.last_y = e.y

    def _mouse_up(self, e):
        self.drawing = False
        if self.tool in ("rect", "circle") and self.current_image:
            self.original_image = self.current_image.copy()
            draw = ImageDraw.Draw(self.current_image)
            sx = self.current_image.size[0] / self._display_img.size[0] if hasattr(self, '_display_img') else 1
            sy = self.current_image.size[1] / self._display_img.size[1] if hasattr(self, '_display_img') else 1
            coords = [(self.last_x * sx, self.last_y * sy), (e.x * sx, e.y * sy)]
            if self.tool == "rect":
                draw.rectangle(coords, outline=self.draw_color, width=self.draw_size)
            else:
                draw.ellipse(coords, outline=self.draw_color, width=self.draw_size)
            self._display()
        elif self.tool == "crop" and self.current_image:
            self.original_image = self.current_image.copy()
            sx = self.current_image.size[0] / self._display_img.size[0] if hasattr(self, '_display_img') else 1
            sy = self.current_image.size[1] / self._display_img.size[1] if hasattr(self, '_display_img') else 1
            box = (int(min(self.last_x, e.x) * sx), int(min(self.last_y, e.y) * sy),
                   int(max(self.last_x, e.x) * sx), int(max(self.last_y, e.y) * sy))
            self.current_image = self.current_image.crop(box)
            self._display()
            self.tool_var.set("brush")
        elif self.tool == "text" and self.current_image:
            text = tk.simpledialog.askstring("Text", "Enter text:") if hasattr(tk, 'simpledialog') else None
            if not text:
                try:
                    from tkinter import simpledialog
                    text = simpledialog.askstring("Text", "Enter text:")
                except Exception:
                    pass
            if text:
                self.original_image = self.current_image.copy()
                draw = ImageDraw.Draw(self.current_image)
                sx = self.current_image.size[0] / self._display_img.size[0] if hasattr(self, '_display_img') else 1
                sy = self.current_image.size[1] / self._display_img.size[1] if hasattr(self, '_display_img') else 1
                try:
                    fnt = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                                             int(self.draw_size * 6 * sx))
                except Exception:
                    fnt = ImageFont.load_default()
                draw.text((e.x * sx, e.y * sy), text, fill=self.draw_color, font=fnt)
                self._display()
        self.canvas.delete("preview")


# ─── Video/Audio Tab ────────────────────────────────────────────────────────

class MediaTab(tk.Frame):
    def __init__(self, parent, log_fn):
        super().__init__(parent, bg=BG)
        self.log = log_fn
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG2, padx=15, pady=10)
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(top, text="MEDIA PLAYER / EDITOR / RECORDER", font=("Consolas", 14, "bold"),
                 fg=ACCENT, bg=BG2).pack(anchor="w")
        tk.Label(top, text="Play, edit, convert, and record video and audio using ffmpeg + mpv",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG2).pack(anchor="w", pady=(2, 8))

        # Player section
        player_frame = tk.LabelFrame(top, text=" PLAYER ", fg=ACCENT, bg=BG2, font=("Consolas", 10, "bold"),
                                      labelanchor="nw", padx=10, pady=8)
        player_frame.pack(fill=tk.X, pady=4)

        prow = tk.Frame(player_frame, bg=BG2)
        prow.pack(fill=tk.X)
        self.media_path = tk.StringVar()
        tk.Entry(prow, textvariable=self.media_path, bg=BG3, fg=TEXT, font=("Consolas", 10),
                 relief=tk.FLAT, borderwidth=4).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(prow, text="Browse", command=self._browse_media, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=6).pack(side=tk.LEFT, padx=4)
        tk.Button(prow, text="Play", command=self._play_media, bg=ACCENT, fg="#000",
                  font=("Consolas", 10, "bold"), relief=tk.FLAT, padx=12).pack(side=tk.LEFT, padx=4)

        # Editor section
        editor_frame = tk.LabelFrame(top, text=" VIDEO EDITOR ", fg=BLUE, bg=BG2, font=("Consolas", 10, "bold"),
                                      labelanchor="nw", padx=10, pady=8)
        editor_frame.pack(fill=tk.X, pady=4)

        # Cut
        cut_row = tk.Frame(editor_frame, bg=BG2)
        cut_row.pack(fill=tk.X, pady=2)
        tk.Label(cut_row, text="Cut:", fg=TEXT, bg=BG2, font=("Consolas", 9), width=8, anchor="w").pack(side=tk.LEFT)
        tk.Label(cut_row, text="From:", fg=TEXT_DIM, bg=BG2, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.cut_start = tk.StringVar(value="00:00:00")
        tk.Entry(cut_row, textvariable=self.cut_start, width=10, bg=BG3, fg=TEXT,
                 font=("Consolas", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Label(cut_row, text="To:", fg=TEXT_DIM, bg=BG2, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.cut_end = tk.StringVar(value="00:01:00")
        tk.Entry(cut_row, textvariable=self.cut_end, width=10, bg=BG3, fg=TEXT,
                 font=("Consolas", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Button(cut_row, text="Cut", command=self._cut_video, bg=BLUE, fg="#fff",
                  font=("Consolas", 9, "bold"), relief=tk.FLAT, padx=10).pack(side=tk.LEFT, padx=4)

        # Convert
        conv_row = tk.Frame(editor_frame, bg=BG2)
        conv_row.pack(fill=tk.X, pady=2)
        tk.Label(conv_row, text="Convert:", fg=TEXT, bg=BG2, font=("Consolas", 9), width=8, anchor="w").pack(side=tk.LEFT)
        self.conv_format = tk.StringVar(value="mp4")
        for fmt in ["mp4", "avi", "mkv", "webm", "mov", "gif", "mp3", "wav", "flac"]:
            tk.Radiobutton(conv_row, text=fmt, variable=self.conv_format, value=fmt,
                           fg=TEXT, bg=BG2, selectcolor=BG3, font=("Consolas", 8)).pack(side=tk.LEFT, padx=2)
        tk.Button(conv_row, text="Convert", command=self._convert_media, bg=BLUE, fg="#fff",
                  font=("Consolas", 9, "bold"), relief=tk.FLAT, padx=10).pack(side=tk.LEFT, padx=4)

        # Extract audio / add audio
        extra_row = tk.Frame(editor_frame, bg=BG2)
        extra_row.pack(fill=tk.X, pady=2)
        tk.Button(extra_row, text="Extract Audio", command=self._extract_audio, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(extra_row, text="Remove Audio", command=self._remove_audio, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(extra_row, text="Merge Videos", command=self._merge_videos, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(extra_row, text="Get Info", command=self._media_info, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(extra_row, text="Thumbnail", command=self._gen_thumbnail, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.LEFT, padx=2)

        # Recorder section
        rec_frame = tk.LabelFrame(top, text=" AUDIO RECORDER ", fg=RED, bg=BG2, font=("Consolas", 10, "bold"),
                                   labelanchor="nw", padx=10, pady=8)
        rec_frame.pack(fill=tk.X, pady=4)

        rec_row = tk.Frame(rec_frame, bg=BG2)
        rec_row.pack(fill=tk.X)
        self.rec_btn = tk.Button(rec_row, text="  RECORD  ", command=self._toggle_record,
                                  bg=RED, fg="#fff", font=("Consolas", 11, "bold"),
                                  relief=tk.FLAT, padx=15, cursor="hand2")
        self.rec_btn.pack(side=tk.LEFT)
        self.rec_status = tk.Label(rec_row, text="Ready", fg=TEXT_DIM, bg=BG2, font=("Consolas", 10))
        self.rec_status.pack(side=tk.LEFT, padx=12)
        self.recording = False
        self.rec_process = None

        # Output
        self.output = scrolledtext.ScrolledText(self, bg=BG2, fg=TEXT, font=("Consolas", 9),
                                                 relief=tk.FLAT, height=8, state=tk.DISABLED)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _log_output(self, text):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def _safe_log(self, text):
        self.after(0, self._log_output, text)

    def _browse_media(self):
        path = filedialog.askopenfilename(filetypes=[
            ("Media", "*.mp4 *.avi *.mkv *.mov *.webm *.mp3 *.wav *.flac *.ogg *.m4a *.wmv *.gif"),
            ("All", "*.*")])
        if path:
            self.media_path.set(path)

    def _play_media(self):
        path = self.media_path.get()
        if not path:
            return
        player = "mpv" if _has("mpv") else "vlc" if _has("vlc") else "xdg-open"
        subprocess.Popen([player, path])
        self._log_output(f"Playing: {path}")

    def _cut_video(self):
        path = self.media_path.get()
        if not path:
            return
        start = self.cut_start.get()
        end = self.cut_end.get()
        ext = Path(path).suffix
        out = str(EXPORTS / f"cut_{datetime.now().strftime('%H%M%S')}{ext}")
        cmd = f'ffmpeg -y -i "{path}" -ss {start} -to {end} -c copy "{out}"'
        self._log_output(f"Cutting {start} -> {end}...")
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Cut saved: {out}"), daemon=True).start()

    def _convert_media(self):
        path = self.media_path.get()
        if not path:
            return
        fmt = self.conv_format.get()
        out = str(EXPORTS / f"converted_{datetime.now().strftime('%H%M%S')}.{fmt}")
        cmd = f'ffmpeg -y -i "{path}" "{out}"'
        self._log_output(f"Converting to {fmt}...")
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Converted: {out}"), daemon=True).start()

    def _extract_audio(self):
        path = self.media_path.get()
        if not path:
            return
        out = str(EXPORTS / f"audio_{datetime.now().strftime('%H%M%S')}.mp3")
        cmd = f'ffmpeg -y -i "{path}" -vn -acodec libmp3lame -q:a 2 "{out}"'
        self._log_output("Extracting audio...")
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Audio saved: {out}"), daemon=True).start()

    def _remove_audio(self):
        path = self.media_path.get()
        if not path:
            return
        ext = Path(path).suffix
        out = str(EXPORTS / f"noaudio_{datetime.now().strftime('%H%M%S')}{ext}")
        cmd = f'ffmpeg -y -i "{path}" -an -c:v copy "{out}"'
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Saved (no audio): {out}"), daemon=True).start()

    def _merge_videos(self):
        files = filedialog.askopenfilenames(filetypes=[("Video", "*.mp4 *.avi *.mkv *.mov *.webm")])
        if len(files) < 2:
            return
        listfile = EXPORTS / "merge_list.txt"
        with open(listfile, "w") as f:
            for fp in files:
                f.write(f"file '{fp}'\n")
        out = str(EXPORTS / f"merged_{datetime.now().strftime('%H%M%S')}.mp4")
        cmd = f'ffmpeg -y -f concat -safe 0 -i "{listfile}" -c copy "{out}"'
        self._log_output(f"Merging {len(files)} files...")
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Merged: {out}"), daemon=True).start()

    def _media_info(self):
        path = self.media_path.get()
        if not path:
            return
        cmd = f'ffprobe -v quiet -print_format json -show_format -show_streams "{path}"'
        code, out, err = _run(cmd)
        if code == 0:
            try:
                info = json.loads(out)
                fmt = info.get("format", {})
                self._log_output(f"\n--- {Path(path).name} ---")
                self._log_output(f"  Format: {fmt.get('format_long_name', '?')}")
                self._log_output(f"  Duration: {float(fmt.get('duration', 0)):.1f}s")
                self._log_output(f"  Size: {int(fmt.get('size', 0)) / 1024 / 1024:.1f} MB")
                self._log_output(f"  Bitrate: {int(fmt.get('bit_rate', 0)) / 1000:.0f} kbps")
                for s in info.get("streams", []):
                    if s["codec_type"] == "video":
                        self._log_output(f"  Video: {s.get('codec_name')} {s.get('width')}x{s.get('height')} {s.get('r_frame_rate')} fps")
                    elif s["codec_type"] == "audio":
                        self._log_output(f"  Audio: {s.get('codec_name')} {s.get('sample_rate')}Hz {s.get('channels')}ch")
            except Exception:
                self._log_output(out[:500])
        else:
            self._log_output(err or "Failed to get info")

    def _gen_thumbnail(self):
        path = self.media_path.get()
        if not path:
            return
        out = str(EXPORTS / f"thumb_{datetime.now().strftime('%H%M%S')}.jpg")
        cmd = f'ffmpeg -y -i "{path}" -vf "thumbnail" -frames:v 1 "{out}"'
        threading.Thread(target=self._run_ffmpeg, args=(cmd, f"Thumbnail: {out}"), daemon=True).start()

    def _toggle_record(self):
        if not self.recording:
            out = str(RECORDINGS / f"recording_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav")
            self.rec_process = subprocess.Popen(
                ["ffmpeg", "-y", "-f", "pulse", "-i", "default", out],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.recording = True
            self.rec_btn.config(text="  STOP  ", bg="#aa0000")
            self.rec_status.config(text=f"Recording... {out}", fg=RED)
            self._log_output(f"Recording started: {out}")
        else:
            if self.rec_process:
                self.rec_process.terminate()
                self.rec_process.wait()
            self.recording = False
            self.rec_btn.config(text="  RECORD  ", bg=RED)
            self.rec_status.config(text="Stopped", fg=TEXT_DIM)
            self._log_output("Recording stopped")

    def _run_ffmpeg(self, cmd, success_msg):
        code, out, err = _run(cmd, timeout=600)
        if code == 0:
            self._safe_log(success_msg)
        else:
            self._safe_log(f"Error: {err[:200]}")


# ─── 3D Effects Tab ─────────────────────────────────────────────────────────

class Effects3DTab(tk.Frame):
    def __init__(self, parent, log_fn):
        super().__init__(parent, bg=BG)
        self.log = log_fn
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG2, padx=15, pady=10)
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(top, text="3D EFFECTS & CONVERTER", font=("Consolas", 14, "bold"),
                 fg=ACCENT, bg=BG2).pack(anchor="w")
        tk.Label(top, text="Convert 2D images to 3D anaglyph, depth maps, stereoscopic pairs",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG2).pack(anchor="w", pady=(2, 8))

        # Input
        row = tk.Frame(top, bg=BG2)
        row.pack(fill=tk.X, pady=4)
        tk.Label(row, text="Input:", fg=TEXT, bg=BG2, font=("Consolas", 10), width=8, anchor="w").pack(side=tk.LEFT)
        self.input_path = tk.StringVar()
        tk.Entry(row, textvariable=self.input_path, bg=BG3, fg=TEXT, font=("Consolas", 10),
                 relief=tk.FLAT, borderwidth=4).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(row, text="Browse", command=self._browse, bg=BG3, fg=TEXT,
                  font=("Consolas", 9), relief=tk.FLAT, padx=6).pack(side=tk.LEFT, padx=4)

        # Effects
        effects_frame = tk.Frame(top, bg=BG2)
        effects_frame.pack(fill=tk.X, pady=8)

        effects = [
            ("Anaglyph 3D (Red-Cyan)", self._anaglyph),
            ("Depth Map", self._depth_map),
            ("Stereoscopic Side-by-Side", self._stereo_sbs),
            ("Emboss 3D", self._emboss_3d),
            ("Pop-Out Effect", self._pop_out),
            ("Cross-Eye 3D", self._cross_eye),
        ]

        for i, (label, cmd) in enumerate(effects):
            r = i // 3
            c = i % 3
            btn = tk.Button(effects_frame, text=label, command=cmd,
                            bg=BG3, fg=TEXT, font=("Consolas", 9), relief=tk.FLAT,
                            padx=10, pady=6, width=22, cursor="hand2",
                            activebackground=BORDER)
            btn.grid(row=r, column=c, padx=4, pady=3, sticky="ew")
        effects_frame.columnconfigure(0, weight=1)
        effects_frame.columnconfigure(1, weight=1)
        effects_frame.columnconfigure(2, weight=1)

        # Depth slider
        depth_row = tk.Frame(top, bg=BG2)
        depth_row.pack(fill=tk.X, pady=4)
        tk.Label(depth_row, text="3D Depth:", fg=TEXT, bg=BG2, font=("Consolas", 10)).pack(side=tk.LEFT)
        self.depth_var = tk.IntVar(value=10)
        tk.Scale(depth_row, from_=1, to=30, orient=tk.HORIZONTAL, variable=self.depth_var,
                 bg=BG2, fg=TEXT, troughcolor=BG3, highlightthickness=0, length=200,
                 font=("Consolas", 8)).pack(side=tk.LEFT, padx=8)

        # Preview canvas
        self.canvas = tk.Canvas(self, bg="#1a1a1a", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.photo = None

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp")])
        if path:
            self.input_path.set(path)

    def _load_image(self):
        path = self.input_path.get()
        if not path or not Path(path).exists():
            messagebox.showwarning("No image", "Select an image first")
            return None
        return Image.open(path).convert("RGB")

    def _show_result(self, img, suffix="3d"):
        out = str(EXPORTS / f"{suffix}_{datetime.now().strftime('%H%M%S')}.png")
        img.save(out)
        cw = self.canvas.winfo_width() or 700
        ch = self.canvas.winfo_height() or 400
        display = img.copy()
        display.thumbnail((cw, ch), Image.LANCZOS)
        self.photo = ImageTk.PhotoImage(display)
        self.canvas.delete("all")
        self.canvas.create_image(cw // 2, ch // 2, image=self.photo, anchor="center")
        self.canvas.create_text(10, 10, text=f"Saved: {out}", fill=ACCENT, anchor="nw", font=("Consolas", 9))

    def _anaglyph(self):
        img = self._load_image()
        if not img:
            return
        depth = self.depth_var.get()
        r, g, b = img.split()
        shifted = Image.merge("RGB", (r, g, b))
        left = shifted.crop((0, 0, img.width - depth, img.height))
        right = img.crop((depth, 0, img.width, img.height))
        rl, _, _ = left.split()
        _, rg, rb = right.split()
        anaglyph = Image.merge("RGB", (rl, rg, rb))
        self._show_result(anaglyph, "anaglyph")

    def _depth_map(self):
        img = self._load_image()
        if not img:
            return
        gray = img.convert("L")
        edges = gray.filter(ImageFilter.FIND_EDGES)
        blurred = gray.filter(ImageFilter.GaussianBlur(5))
        depth = Image.blend(blurred, edges, 0.5)
        enhanced = ImageEnhance.Contrast(depth).enhance(2.0)
        self._show_result(enhanced.convert("RGB"), "depthmap")

    def _stereo_sbs(self):
        img = self._load_image()
        if not img:
            return
        depth = self.depth_var.get()
        w, h = img.size
        left = img.crop((depth, 0, w, h))
        right = img.crop((0, 0, w - depth, h))
        stereo = Image.new("RGB", (left.width * 2 + 20, h), (0, 0, 0))
        stereo.paste(left, (0, 0))
        stereo.paste(right, (left.width + 20, 0))
        self._show_result(stereo, "stereo_sbs")

    def _emboss_3d(self):
        img = self._load_image()
        if not img:
            return
        embossed = img.filter(ImageFilter.EMBOSS)
        enhanced = ImageEnhance.Contrast(embossed).enhance(1.5)
        bright = ImageEnhance.Brightness(enhanced).enhance(1.2)
        self._show_result(bright, "emboss3d")

    def _pop_out(self):
        img = self._load_image()
        if not img:
            return
        depth = self.depth_var.get()
        r, g, b = img.split()
        r_shifted = Image.new("L", img.size)
        r_shifted.paste(r.crop((depth, 0, img.width, img.height)), (0, 0))
        b_shifted = Image.new("L", img.size)
        b_shifted.paste(b.crop((0, 0, img.width - depth, img.height)), (depth, 0))
        result = Image.merge("RGB", (r_shifted, g, b_shifted))
        contrast = ImageEnhance.Contrast(result).enhance(1.3)
        self._show_result(contrast, "popout")

    def _cross_eye(self):
        img = self._load_image()
        if not img:
            return
        depth = self.depth_var.get()
        w, h = img.size
        right = img.crop((depth, 0, w, h))
        left = img.crop((0, 0, w - depth, h))
        cross = Image.new("RGB", (left.width * 2 + 20, h), (0, 0, 0))
        cross.paste(right, (0, 0))
        cross.paste(left, (right.width + 20, 0))
        self._show_result(cross, "crosseye")


# ─── Tools Tab ──────────────────────────────────────────────────────────────

class ToolsTab(tk.Frame):
    def __init__(self, parent, log_fn):
        super().__init__(parent, bg=BG)
        self.log = log_fn
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG2, padx=15, pady=10)
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(top, text="INSTALLED TOOLS", font=("Consolas", 14, "bold"),
                 fg=ACCENT, bg=BG2).pack(anchor="w")
        tk.Label(top, text="External apps configured and ready to launch",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG2).pack(anchor="w", pady=(2, 8))

        tools_frame = tk.Frame(self, bg=BG, padx=10, pady=5)
        tools_frame.pack(fill=tk.BOTH, expand=True)

        apps = [
            ("GIMP", "gimp", "Advanced image editor — layers, filters, plugins", "Image Editor"),
            ("Inkscape", "inkscape", "Vector graphics editor — SVG, illustrations", "Vector Editor"),
            ("Audacity", "audacity", "Audio editor — record, mix, effects, export", "Audio Editor"),
            ("VLC", "vlc", "Universal media player — plays any format", "Media Player"),
            ("mpv", "mpv", "Lightweight video player — GPU accelerated", "Video Player"),
            ("ImageMagick", "display", "CLI image processor — convert, resize, effects", "Image Tool"),
            ("ffmpeg", "ffmpeg", "Video/audio encoder — convert, cut, merge, stream", "Media Engine"),
            ("yt-dlp", "yt-dlp", "Download videos from YouTube, TikTok, etc.", "Downloader"),
            ("wget", "wget", "Download files and clone entire websites", "Web Tool"),
            ("curl", "curl", "Transfer data from URLs — HTTP, FTP, etc.", "Network Tool"),
        ]

        for i, (name, cmd, desc, category) in enumerate(apps):
            installed = _has(cmd)
            row = tk.Frame(tools_frame, bg=BG2, padx=12, pady=8,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill=tk.X, pady=3, padx=5)

            status_color = ACCENT if installed else RED
            tk.Label(row, text="●", fg=status_color, bg=BG2, font=("Consolas", 12)).pack(side=tk.LEFT, padx=(0, 8))

            info = tk.Frame(row, bg=BG2)
            info.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(info, text=name, fg=TEXT if installed else TEXT_DIM, bg=BG2,
                     font=("Consolas", 11, "bold")).pack(anchor="w")
            tk.Label(info, text=f"{desc}  [{category}]", fg=TEXT_DIM, bg=BG2,
                     font=("Consolas", 8)).pack(anchor="w")

            if installed:
                version = ""
                if cmd in ("ffmpeg", "curl", "wget"):
                    _, v, _ = _run(f"{cmd} --version 2>&1 | head -1")
                    version = v[:40] if v else ""
                elif cmd == "yt-dlp":
                    _, v, _ = _run(f"yt-dlp --version 2>&1")
                    version = v.strip()
                if version:
                    tk.Label(info, text=version, fg=TEXT_DIM, bg=BG2, font=("Consolas", 7)).pack(anchor="w")

                if cmd in ("gimp", "inkscape", "audacity", "vlc"):
                    tk.Button(row, text="Launch", command=lambda c=cmd: subprocess.Popen([c]),
                              bg=ACCENT, fg="#000", font=("Consolas", 9, "bold"),
                              relief=tk.FLAT, padx=10, cursor="hand2").pack(side=tk.RIGHT)
            else:
                tk.Label(row, text="NOT INSTALLED", fg=RED, bg=BG2, font=("Consolas", 9)).pack(side=tk.RIGHT)


# ─── Main Application ──────────────────────────────────────────────────────

class AegisStudio:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"AEGIS Studio v{__version__} — Multimedia Hub")
        self.root.geometry("1100x800")
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        try:
            self.root.attributes('-alpha', 0.97)
        except Exception:
            pass

        self._build()

    def _build(self):
        # Header
        header = tk.Frame(self.root, bg=BG2, height=45)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        logo = tk.Canvas(header, width=28, height=28, bg=BG2, highlightthickness=0)
        logo.pack(side=tk.LEFT, padx=(12, 6), pady=8)
        logo.create_polygon(14, 2, 26, 10, 22, 24, 6, 24, 2, 10,
                            fill="#003322", outline=ACCENT, width=2)
        logo.create_text(14, 14, text="S", fill=ACCENT, font=("Consolas", 9, "bold"))

        tk.Label(header, text="AEGIS Studio", font=("Consolas", 14, "bold"),
                 fg=ACCENT, bg=BG2).pack(side=tk.LEFT)
        tk.Label(header, text=f"v{__version__}  |  Multimedia Hub",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG2).pack(side=tk.LEFT, padx=10)

        tk.Button(header, text="Open Exports", command=lambda: subprocess.Popen(["xdg-open", str(EXPORTS)]),
                  bg=BG3, fg=TEXT, font=("Consolas", 9), relief=tk.FLAT, padx=8).pack(side=tk.RIGHT, padx=8, pady=8)

        # Tabs
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=TEXT,
                         padding=[14, 6], font=("Consolas", 10, "bold"))
        style.map("TNotebook.Tab",
                   background=[("selected", BG3)],
                   foreground=[("selected", ACCENT)])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        def log(msg):
            print(msg)

        self.notebook.add(DownloaderTab(self.notebook, log), text="  Downloader  ")
        self.notebook.add(ImageEditorTab(self.notebook, log), text="  Image Editor  ")
        self.notebook.add(MediaTab(self.notebook, log), text="  Video / Audio  ")
        self.notebook.add(Effects3DTab(self.notebook, log), text="  3D Effects  ")
        self.notebook.add(ToolsTab(self.notebook, log), text="  Tools  ")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    if not HAS_PIL:
        print("Warning: Pillow not installed — image editing disabled")
    app = AegisStudio()
    app.run()
