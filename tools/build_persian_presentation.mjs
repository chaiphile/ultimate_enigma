import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";

const artifactTool = await import(pathToFileURL("C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs").href);
const { Presentation, PresentationFile } = artifactTool;

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), "..");
const THREAD_ID = process.env.CODEX_THREAD_ID || "manual-ultimate-enigma-persian";
const WORKSPACE = path.join(os.tmpdir(), "codex-presentations", THREAD_ID, "ultimate-enigma-persian");
const TMP_DIR = path.join(WORKSPACE, "tmp");
const PREVIEW_DIR = path.join(TMP_DIR, "preview");
const LAYOUT_DIR = path.join(TMP_DIR, "layout");
const QA_DIR = path.join(TMP_DIR, "qa");
const ASSET_DIR = path.join(TMP_DIR, "assets");
const OUTPUT_DIR = path.join(REPO_ROOT, "outputs");
const FINAL_PPTX = path.join(OUTPUT_DIR, "ultimate-enigma-persian-presentation.pptx");

const W = 1280;
const H = 720;
const C = {
  navy: "#081826",
  ink: "#102332",
  text: "#142335",
  muted: "#5a6b78",
  pale: "#eef5f4",
  white: "#ffffff",
  teal: "#0f766e",
  mint: "#9fd8c4",
  amber: "#f4b942",
  red: "#c2410c",
  blue: "#2563eb",
  line: "#d7e2df",
  panel: "#f8fbfa",
};
const FONT = "Vazirmatn";

function rtlParagraph(value, alignment = "right", runStyle = {}) {
  return [{
    paragraphStyle: {
      rtl: true,
      bidi: true,
      alignment,
      tabStops: [],
    },
    runs: [{
      run: value,
      textStyle: {
        typeface: FONT,
        ...runStyle,
      },
    }],
  }];
}

function addBg(slide, variant = "light") {
  slide.background.fill = variant === "dark" ? C.navy : C.pale;
  if (variant === "dark") {
    slide.shapes.add({
      geometry: "rect",
      position: { left: 0, top: 0, width: W, height: H },
      fill: C.navy,
      line: { style: "solid", fill: C.navy, width: 0 },
    });
    slide.shapes.add({
      geometry: "rect",
      position: { left: 0, top: 602, width: W, height: 118 },
      fill: "#0f2a35",
      line: { style: "solid", fill: "#0f2a35", width: 0 },
    });
  } else {
    slide.shapes.add({
      geometry: "rect",
      position: { left: 0, top: 0, width: W, height: H },
      fill: C.pale,
      line: { style: "solid", fill: C.pale, width: 0 },
    });
    slide.shapes.add({
      geometry: "rect",
      position: { left: 0, top: 0, width: W, height: 90 },
      fill: C.white,
      line: { style: "solid", fill: C.line, width: 1 },
    });
  }
}

function text(slide, value, x, y, w, h, opts = {}) {
  const s = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  const alignment = opts.align ?? "right";
  s.text.set(rtlParagraph(value, alignment, {
    fontSize: `${opts.size ?? 24}px`,
    bold: opts.bold ?? false,
    color: opts.color ?? C.text,
  }));
  s.text.style = {
    typeface: FONT,
    fontSize: opts.size ?? 24,
    bold: opts.bold ?? false,
    color: opts.color ?? C.text,
    alignment,
    verticalAlignment: opts.valign ?? "top",
    lineSpacing: opts.lineSpacing ?? 1.1,
    autoFit: "shrinkText",
    insets: { top: 4, right: 8, bottom: 4, left: 8 },
  };
  return s;
}

function ltrText(slide, value, x, y, w, h, opts = {}) {
  const s = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  s.text = value;
  s.text.style = {
    typeface: opts.typeface ?? "Aptos",
    fontSize: opts.size ?? 16,
    bold: opts.bold ?? false,
    color: opts.color ?? C.muted,
    alignment: opts.align ?? "left",
    verticalAlignment: opts.valign ?? "top",
    autoFit: "shrinkText",
  };
  return s;
}

function title(slide, value, subtitle = "") {
  text(slide, value, 520, 24, 680, 56, { size: 33, bold: true, color: C.ink });
  if (subtitle) text(slide, subtitle, 88, 32, 390, 40, { size: 16, color: C.muted });
}

function footer(slide, num) {
  ltrText(slide, "Ultimate Enigma Messenger", 825, 676, 360, 26, { size: 12, color: C.muted, align: "right" });
  ltrText(slide, String(num).padStart(2, "0"), 74, 678, 48, 24, { size: 12, bold: true, color: C.teal });
}

function card(slide, x, y, w, h, fill = C.white, line = C.line) {
  return slide.shapes.add({
    geometry: "roundRect",
    position: { left: x, top: y, width: w, height: h },
    fill,
    line: { style: "solid", fill: line, width: 1 },
    borderRadius: 8,
    shadow: "shadow-sm",
  });
}

function pill(slide, label, x, y, w, fill = C.teal, color = C.white) {
  const p = slide.shapes.add({
    geometry: "roundRect",
    position: { left: x, top: y, width: w, height: 34 },
    fill,
    line: { style: "solid", fill, width: 0 },
    borderRadius: 16,
  });
  p.text.set(rtlParagraph(label, "center", {
    fontSize: "14px",
    bold: true,
    color,
  }));
  p.text.style = {
    typeface: FONT,
    fontSize: 14,
    bold: true,
    color,
    alignment: "center",
    verticalAlignment: "middle",
    autoFit: "shrinkText",
  };
  return p;
}

function pillLtr(slide, label, x, y, w, fill = "#d9ebe7", color = C.ink) {
  const p = slide.shapes.add({
    geometry: "roundRect",
    position: { left: x, top: y, width: w, height: 34 },
    fill,
    line: { style: "solid", fill, width: 0 },
    borderRadius: 16,
  });
  p.text = label;
  p.text.style = {
    typeface: "Aptos",
    fontSize: 14,
    bold: true,
    color,
    alignment: "center",
    verticalAlignment: "middle",
    autoFit: "shrinkText",
  };
  return p;
}

function addBulletList(slide, items, x, y, w, h, opts = {}) {
  const s = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  s.text.set(items.map((item) => ({
    bulletCharacter: "•",
    marginLeft: 22,
    indent: -12,
    paragraphStyle: {
      rtl: true,
      bidi: true,
      alignment: "right",
      tabStops: [],
    },
    runs: [{
      run: item,
      textStyle: {
        typeface: FONT,
        fontSize: `${opts.size ?? 21}px`,
        color: opts.color ?? C.text,
      },
    }],
  })));
  s.text.style = {
    typeface: FONT,
    fontSize: opts.size ?? 21,
    color: opts.color ?? C.text,
    alignment: "right",
    lineSpacing: opts.lineSpacing ?? 1.25,
    autoFit: "shrinkText",
    insets: { top: 4, right: 12, bottom: 4, left: 4 },
  };
  return s;
}

function addMiniLock(slide, cx, cy, scale = 1, color = C.amber) {
  slide.shapes.add({
    geometry: "arc",
    position: { left: cx - 44 * scale, top: cy - 58 * scale, width: 88 * scale, height: 80 * scale },
    fill: "none",
    line: { style: "solid", fill: color, width: 7 * scale },
  });
  slide.shapes.add({
    geometry: "roundRect",
    position: { left: cx - 62 * scale, top: cy - 10 * scale, width: 124 * scale, height: 92 * scale },
    fill: color,
    line: { style: "solid", fill: color, width: 0 },
    borderRadius: 10 * scale,
  });
  slide.shapes.add({
    geometry: "ellipse",
    position: { left: cx - 11 * scale, top: cy + 24 * scale, width: 22 * scale, height: 22 * scale },
    fill: C.navy,
    line: { style: "solid", fill: C.navy, width: 0 },
  });
}

function addNode(slide, label, x, y, w, h, fill = C.white, accent = C.teal) {
  card(slide, x, y, w, h, fill, C.line);
  slide.shapes.add({
    geometry: "rect",
    position: { left: x + w - 9, top: y, width: 9, height: h },
    fill: accent,
    line: { style: "solid", fill: accent, width: 0 },
  });
  text(slide, label, x + 16, y + 17, w - 34, h - 26, { size: 18, bold: true, color: C.ink });
}

function addAlgoRow(slide, label, code, note, y) {
  card(slide, 150, y, 980, 72, C.white, C.line);
  text(slide, label, 920, y + 16, 180, 30, { size: 21, bold: true, color: C.teal });
  ltrText(slide, code, 420, y + 17, 420, 28, { size: 18, bold: true, color: C.ink, align: "center", typeface: "Aptos" });
  if (note) text(slide, note, 190, y + 16, 210, 30, { size: 18, color: C.muted });
}

function arrow(slide, x1, y1, x2, y2, color = C.teal) {
  slide.shapes.add({
    geometry: "line",
    position: { left: x1, top: y1, width: x2 - x1, height: y2 - y1 },
    fill: "none",
    line: { style: "solid", fill: color, width: 3 },
  });
  slide.shapes.add({
    geometry: "triangle",
    position: { left: x2 - 9, top: y2 - 7, width: 15, height: 14, rotation: x2 >= x1 ? 90 : 270 },
    fill: color,
    line: { style: "solid", fill: color, width: 0 },
  });
}

function makeDeck() {
  const p = Presentation.create({ slideSize: { width: W, height: H } });

  // 1
  {
    const s = p.slides.add();
    addBg(s, "dark");
    pill(s, "پروژه پایانی", 970, 72, 160, C.teal);
    ltrText(s, "Ultimate Enigma Messenger", 235, 174, 840, 90, { size: 52, bold: true, color: C.white, align: "center", typeface: "Aptos Display" });
    text(s, "پیام‌رسان رمزنگاری‌شده، آفلاین و مقاوم در برابر تهدیدهای امروز و فردا", 250, 276, 780, 68, { size: 25, color: "#dbe9e6", align: "center" });
    addMiniLock(s, 640, 458, 1.25, C.amber);
    ltrText(s, "Python • Tkinter • AES-GCM • RSA-OAEP • Double Ratchet • PQC", 282, 633, 716, 30, { size: 17, color: "#b9c9c8", align: "center" });
  }

  // 2
  {
    const s = p.slides.add();
    addBg(s, "light");
    text(s, "هنرستان فنی راه دانش مریوان", 150, 185, 980, 82, { size: 48, bold: true, color: C.ink, align: "center" });
    text(s, "بهار ۱۴۰۵ ش.ه", 350, 290, 580, 58, { size: 35, bold: true, color: C.teal, align: "center" });
    card(s, 250, 420, 780, 96, C.white, C.line);
    text(s, "ارائه پروژه نرم‌افزاری در حوزه امنیت، رمزنگاری و پیام‌رسانی امن", 278, 447, 724, 42, { size: 24, color: C.text, align: "center" });
    footer(s, 2);
  }

  // 3
  {
    const s = p.slides.add();
    addBg(s, "light");
    text(s, "آرتین احسان بخش", 160, 145, 960, 70, { size: 47, bold: true, color: C.ink, align: "center" });
    text(s, "دانش‌آموز پایه دهم رشته شبکه و نرم‌افزار", 160, 236, 960, 52, { size: 31, color: C.teal, align: "center" });
    text(s, "شهرستان مریوان", 160, 304, 960, 44, { size: 28, color: C.muted, align: "center" });
    card(s, 300, 432, 680, 86, C.white, C.line);
    text(s, "تمرکز پروژه: ساخت یک ابزار محلی برای رمزنگاری پیام، فایل، کلیدها و ارتباط امن میان دوستان", 334, 455, 612, 44, { size: 21, color: C.text, align: "center" });
    footer(s, 3);
  }

  // 4
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "مسئله‌ای که پروژه حل می‌کند", "امنیت در ارتباطات شخصی");
    card(s, 725, 145, 440, 390);
    text(s, "چالش‌ها", 1000, 170, 130, 34, { size: 24, bold: true, color: C.red });
    addBulletList(s, [
      "پیام‌های معمولی در مسیر یا روی دستگاه قابل افشا هستند",
      "رمز عبور ضعیف و ذخیره‌سازی ساده کلیدها خطرناک است",
      "حمله‌های آینده با رایانه‌های کوانتومی باید از امروز جدی گرفته شوند",
      "رابط کاربری امنیتی اگر سخت باشد، درست استفاده نمی‌شود",
    ], 765, 220, 355, 250, { size: 20 });
    card(s, 115, 145, 520, 390, C.navy, "#17394a");
    text(s, "ایده اصلی", 360, 174, 230, 42, { size: 28, bold: true, color: C.white });
    text(s, "یک پیام‌رسان آفلاین که انتقال پیام را به کاربر واگذار می‌کند، اما رمزنگاری، امضا، مدیریت کلید، دوستان و فایل‌ها را در یک محیط گرافیکی امن انجام می‌دهد.", 155, 235, 430, 156, { size: 25, color: "#e8f3ef" });
    pill(s, "حریم خصوصی، نه شعار؛ یک طراحی مهندسی", 205, 438, 330, C.amber, C.navy);
    footer(s, 4);
  }

  // 5
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "نمای کلی راه‌حل", "از متن ساده تا بسته رمزنگاری‌شده");
    const xs = [890, 650, 410, 170];
    const labels = ["متن یا فایل", "کلید نشست", "رمزنگاری و امضا", "خروجی امن"];
    for (let i = 0; i < labels.length; i++) addNode(s, labels[i], xs[i], 220, 180, 92, i === 1 ? "#fef7df" : C.white, i === 2 ? C.amber : C.teal);
    arrow(s, 890, 266, 830, 266);
    arrow(s, 650, 266, 590, 266);
    arrow(s, 410, 266, 350, 266);
    addBulletList(s, [
      "AES-256-GCM برای رمزنگاری سریع پیام و فایل",
      "RSA-OAEP و X25519 برای تبادل یا پوشش کلید",
      "پروتکل رتچت دوگانه برای محرمانگی رو به جلو",
      "الگوریتم‌های پساکوانتومی برای امنیت آینده",
    ], 185, 400, 910, 150, { size: 23 });
    footer(s, 5);
  }

  // 6
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "معماری نرم‌افزار", "MVC هفت‌لایه با سرویس‌های مستقل");
    addNode(s, "لایه نمایش\nتب‌های رابط کاربری", 820, 150, 260, 92, C.white, C.blue);
    ltrText(s, "Views", 846, 206, 92, 22, { size: 13, color: C.blue, bold: true });
    addNode(s, "کنترلرها\nهماهنگی جریان برنامه", 510, 150, 260, 92, C.white, C.teal);
    ltrText(s, "Controllers", 538, 206, 125, 22, { size: 13, color: C.teal, bold: true });
    addNode(s, "سرویس‌ها\nمنطق رمزنگاری و فایل", 200, 150, 260, 92, C.white, C.amber);
    ltrText(s, "Services", 228, 206, 100, 22, { size: 13, color: C.amber, bold: true });
    addNode(s, "مدل‌ها\nساختار پیام و دوست", 820, 330, 260, 92, C.white, C.teal);
    ltrText(s, "Models", 846, 386, 95, 22, { size: 13, color: C.teal, bold: true });
    addNode(s, "امنیت\nحافظه محافظ و قفل‌گذاری", 510, 330, 260, 92, C.white, C.red);
    ltrText(s, "Security", 538, 386, 105, 22, { size: 13, color: C.red, bold: true });
    addNode(s, "پایگاه داده\nذخیره‌سازی رمزگذاری‌شده", 200, 330, 260, 92, C.white, C.blue);
    ltrText(s, "SQLCipher / SQLite", 228, 386, 155, 22, { size: 13, color: C.blue, bold: true });
    card(s, 355, 510, 570, 74, C.navy, "#17394a");
    text(s, "EventBus: ارتباط رویدادمحور میان تب‌ها، سرویس‌ها و کنترلرها", 385, 531, 510, 32, { size: 22, bold: true, color: C.white, align: "center" });
    footer(s, 6);
  }

  // 7
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "قلب رمزنگاری پروژه", "ترکیب الگوریتم‌های کلاسیک و آینده‌نگر");
    addAlgoRow(s, "محرمانگی پیام", "AES-256-GCM  |  XChaCha20-Poly1305", "رمزنگاری سریع", 142);
    addAlgoRow(s, "تبادل کلید", "RSA-4096  |  X25519 ECDH", "کلید امن", 228);
    addAlgoRow(s, "امنیت مکالمه", "Double Ratchet", "کلیدهای زنجیره‌ای", 314);
    addAlgoRow(s, "پساکوانتومی", "Kyber768  |  Dilithium3  |  liboqs", "آینده‌نگر", 400);
    addAlgoRow(s, "عبور رمز", "Argon2id", "حافظه‌سخت", 486);
    footer(s, 7);
  }

  // 8
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "امنیت فراتر از الگوریتم", "محافظت از کلیدها در حافظه، دیسک و زمان اجرا");
    card(s, 802, 150, 310, 360, C.navy, "#17394a");
    addMiniLock(s, 957, 255, 0.86, C.amber);
    ltrText(s, "Emergency Lock", 820, 362, 274, 36, { size: 25, bold: true, color: C.white, align: "center", typeface: "Aptos" });
    text(s, "پاک‌سازی فوری کلیدها و نیاز به رمز اصلی + TOTP برای بازگشایی", 840, 412, 235, 60, { size: 18, color: "#dcebea", align: "center" });
    addBulletList(s, [
      "رشته امن با پاک‌سازی چندمرحله‌ای برای داده‌های حساس",
      "بافر محافظت‌شده برای نگهداری کلیدهای زنجیره‌ای",
      "قفل‌شدن حافظه برای کاهش نشت در حافظه جانبی",
      "محافظت ضد دامپ و ضد دستکاری در فایل اجرایی",
      "قفل‌گذاری نمایی پس از تلاش‌های ناموفق",
    ], 155, 158, 560, 330, { size: 22 });
    footer(s, 8);
  }

  // 9
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "تجربه کاربری", "امنیت باید قابل استفاده باشد");
    const tabs = ["Encrypt", "Decrypt", "Friends", "Files", "Secret", "Trust", "About"];
    let x = 112;
    for (const t of tabs) {
      pillLtr(s, t, x, 150, 132, t === "Encrypt" ? C.teal : "#d9ebe7", t === "Encrypt" ? C.white : C.ink);
      x += 148;
    }
    card(s, 126, 226, 1028, 320, C.white, C.line);
    text(s, "نمونه جریان کار", 880, 258, 220, 40, { size: 27, bold: true, color: C.ink });
    addBulletList(s, [
      "کاربر پیام را وارد می‌کند و روش رمزنگاری را انتخاب می‌کند",
      "برنامه کلید مناسب را از دوست، راز مشترک یا Ratchet پیدا می‌کند",
      "خروجی Base64 تولید می‌شود و می‌تواند از هر کانالی ارسال شود",
      "گیرنده با همان برنامه پیام را رمزگشایی و امضا را بررسی می‌کند",
    ], 188, 320, 880, 150, { size: 23 });
    footer(s, 9);
  }

  // 10
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "کیفیت و آزمون", "پروژه فقط ایده نیست؛ تست دارد");
    card(s, 820, 160, 300, 250, C.navy, "#17394a");
    text(s, "+۵۵۰", 850, 198, 240, 78, { size: 64, bold: true, color: C.amber, align: "center" });
    text(s, "تست خودکار", 865, 290, 210, 42, { size: 26, bold: true, color: C.white, align: "center" });
    text(s, "در ۳۶ فایل تست", 870, 344, 200, 32, { size: 20, color: "#dbe9e6", align: "center" });
    addBulletList(s, [
      "تست رمزنگاری، پایگاه داده، رمز یک‌بارمصرف، رتچت دوگانه و پساکوانتومی",
      "تست ضد دستکاری با شبیه‌سازی رابط‌های ویندوز",
      "fixture ایزوله برای پایگاه داده تا تست‌ها روی داده واقعی اثر نگذارند",
      "تست خطاها، زمان‌سنجی، همزمانی و پاک‌سازی حافظه",
    ], 150, 170, 560, 260, { size: 23 });
    s.charts.add("bar", {
      position: { left: 170, top: 472, width: 900, height: 130 },
      categories: ["Crypto", "Services", "UI/Controllers", "Security", "Database"],
      series: [{ name: "پوشش موضوعی", values: [5, 5, 4, 5, 4], fill: C.teal }],
      hasLegend: false,
      barOptions: { direction: "bar", grouping: "clustered", gapWidth: 45 },
      xAxis: { visible: false, majorGridlines: null },
      yAxis: { textStyle: { fill: C.muted, fontSize: 13 }, line: { style: "solid", fill: C.line, width: 1 } },
      dataLabels: { showValue: false },
      chartFill: C.pale,
      plotAreaFill: C.pale,
    });
    footer(s, 10);
  }

  // 11
  {
    const s = p.slides.add();
    addBg(s, "light");
    title(s, "محدودیت‌ها و مسیر آینده", "نگاه صادقانه به امنیت");
    card(s, 735, 155, 390, 360);
    text(s, "محدودیت‌ها", 920, 185, 160, 34, { size: 25, bold: true, color: C.red });
    addBulletList(s, [
      "Self-destruct تضمین حذف روی دستگاه گیرنده نیست",
      "ضد دستکاری فقط در نسخه exe فعال می‌شود",
      "PQC به liboqs و DLL مناسب نیاز دارد",
    ], 775, 238, 305, 180, { size: 21 });
    card(s, 160, 155, 440, 360);
    text(s, "گام‌های بعدی", 385, 185, 170, 34, { size: 25, bold: true, color: C.teal });
    addBulletList(s, [
      "بهبود بسته‌بندی نصب ویندوز",
      "افزودن راهنمای تصویری داخل برنامه",
      "بررسی امنیتی مستقل و افزایش پوشش تست",
      "افزودن export/import ساده‌تر برای تبادل کلیدها",
    ], 205, 238, 330, 200, { size: 21 });
    footer(s, 11);
  }

  // 12
  {
    const s = p.slides.add();
    addBg(s, "dark");
    text(s, "جمع‌بندی", 0, 96, W, 60, { size: 44, bold: true, color: C.amber, align: "center" });
    text(s, "Ultimate Enigma Messenger نشان می‌دهد که می‌توان مفاهیم پیشرفته امنیتی را در یک نرم‌افزار دسکتاپ قابل استفاده پیاده‌سازی کرد: رمزنگاری ترکیبی، مدیریت کلید، احراز هویت، امنیت حافظه، تست گسترده و معماری قابل توسعه.", 210, 210, 860, 150, { size: 27, color: C.white, align: "center" });
    card(s, 315, 430, 650, 86, "#0f2a35", "#244957");
    text(s, "حریم خصوصی زمانی واقعی است که طراحی، پیاده‌سازی و تجربه کاربری کنار هم قرار بگیرند.", 350, 452, 580, 44, { size: 23, color: "#e3f0ed", align: "center" });
    text(s, "سپاس از توجه شما", 0, 606, W, 42, { size: 28, bold: true, color: C.mint, align: "center" });
  }

  return p;
}

async function writeBlob(file, blob) {
  await fs.writeFile(file, new Uint8Array(await blob.arrayBuffer()));
}

async function main() {
  for (const dir of [TMP_DIR, PREVIEW_DIR, LAYOUT_DIR, QA_DIR, ASSET_DIR, OUTPUT_DIR]) {
    await fs.mkdir(dir, { recursive: true });
  }

  await fs.writeFile(path.join(TMP_DIR, "source-notes.txt"), [
    "Source notes for Ultimate Enigma Persian presentation",
    "",
    "User-provided content:",
    "- Required slide 1: quick title.",
    "- Required slide 2: هنرستان فنی راه دانش مریوان بهار 1405 ش.ه",
    "- Required slide 3: آرتین احسان بخش دانش آموز پایه دهم رشته شبکه و نرم افزار شهرستان مریوان",
    "",
    "Local project sources:",
    "- readme.md: project overview, feature list, author/version metadata, testing summary.",
    "- AGENTS.md: architecture notes, commands, key gotchas, testing notes.",
    "- docs/ARCHITECTURE.md: MVC/service/EventBus architecture, directory structure, threading model.",
    "- docs/SECURITY.md: cryptographic primitives, threat model, memory security, anti-tamper, TOTP, lockout.",
    "- docs/SCIENTIFIC_REPORT.md: cryptographic foundations, standards, test count, PQC details.",
    "",
    "External sources/assets:",
    "- Vazirmatn variable TTF from the Google Fonts repository, used as the requested Persian typeface deliverable.",
    "- No external images or unsourced logos are used. Visuals are editable native shapes/charts created in the deck.",
  ].join("\n"), "utf8");

  await fs.writeFile(path.join(TMP_DIR, "slide-plan.txt"), [
    "Create mode slide plan",
    "",
    "Style:",
    "- Slide size: 1280x720 px, widescreen.",
    "- Palette: dominant deep navy #081826 and pale mint #eef5f4, support teal #0f766e and white #ffffff, accent amber #f4b942, warning red #c2410c.",
    "- Fonts: Vazirmatn for Persian text; Aptos/Aptos Display for Latin-only technical labels.",
    "- RTL handling: Persian text uses structured paragraph runs with paragraphStyle.rtl=true and paragraphStyle.bidi=true, plus right alignment. Mixed Persian/Latin content is split into separate RTL and LTR text boxes where practical.",
    "- Animation note: @oai/artifact-tool exposes no documented native PowerPoint timeline/transition animation API; deck uses editable visual motion cues, shadows, staged diagram layout, and emphasis layers instead of unsupported OOXML animation hacks.",
    "",
    "Slides:",
    "1. Quick title / project name.",
    "2. School and season.",
    "3. Student introduction.",
    "4. Problem statement.",
    "5. Solution flow.",
    "6. Architecture.",
    "7. Cryptographic core.",
    "8. Defense-in-depth security.",
    "9. User experience.",
    "10. Testing and quality.",
    "11. Limitations and roadmap.",
    "12. Closing summary.",
  ].join("\n"), "utf8");

  const presentation = makeDeck();

  for (const [index, slide] of presentation.slides.items.entries()) {
    const stem = `slide-${String(index + 1).padStart(2, "0")}`;
    const png = await presentation.export({ slide, format: "png", scale: 1 });
    await writeBlob(path.join(PREVIEW_DIR, `${stem}.png`), png);
    const layout = await slide.export({ format: "layout" });
    await fs.writeFile(path.join(LAYOUT_DIR, `${stem}.layout.json`), await layout.text(), "utf8");
  }

  const montage = await presentation.export({ format: "webp", montage: true, scale: 1 });
  await writeBlob(path.join(PREVIEW_DIR, "deck-montage.webp"), montage);

  const pptx = await PresentationFile.exportPptx(presentation);
  await pptx.save(FINAL_PPTX);

  const stat = await fs.stat(FINAL_PPTX);
  await fs.writeFile(path.join(QA_DIR, "visual-qa.txt"), [
    "Visual QA",
    "",
    `Final PPTX: ${FINAL_PPTX}`,
    `Slide count: ${presentation.slides.items.length}`,
    `PPTX size: ${stat.size} bytes`,
    "Rendered every slide to PNG and created a montage.",
    "Deck uses editable text boxes, shapes, and one native chart.",
    "Persian text uses Vazirmatn typeface and structured RTL/BiDi paragraph styles.",
    "Mixed Persian/Latin labels were separated into RTL and LTR text boxes on dense technical slides.",
    "Native PowerPoint animation timelines were not added because artifact-tool has no documented animation/transition API and the skill forbids direct OOXML mutation.",
    "No external images or unsourced logos are used.",
  ].join("\n"), "utf8");

  console.log(JSON.stringify({
    finalPptx: FINAL_PPTX,
    workspace: WORKSPACE,
    slideCount: presentation.slides.items.length,
    size: stat.size,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
