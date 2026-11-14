package com.macnuron.app;

import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

/** Material 3 style tokens (dynamic colour on Android 12+, static baseline otherwise) and small view factories. */
final class Ui {
    final float d;
    final boolean night;
    int primary, onPrimary, primaryContainer, onPrimaryContainer, surface, onSurface, onSurfaceVariant,
        container, containerHigh, error, errorContainer, onErrorContainer, outline;

    Ui(Context c) {
        d = c.getResources().getDisplayMetrics().density;
        int mode = themeMode(c);
        night = mode == 2 || (mode == 0 && (c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES);
        int sch = scheme(c);   // 0 = Liquid Glass (macOS Blue, default), 1 = dynamic (Material You, Android 12+), 2 = classic (neutral black/white)
        if (sch == 1 && Build.VERSION.SDK_INT >= 31) dynamic(c); else if (sch == 2) classic(); else brand();
        error = night ? 0xFFF2B8B5 : 0xFFB3261E;
        errorContainer = night ? 0xFF8C1D18 : 0xFFF9DEDC;
        onErrorContainer = night ? 0xFFF9DEDC : 0xFF410E0B;
    }

    // ---- settings (SharedPreferences "xnuron"): theme 0 = system, 1 = light, 2 = dark; dynamic = Material You colours from the wallpaper (Android 12+), off by default
    static int themeMode(Context c) {
        try { return c.getSharedPreferences("xnuron", Context.MODE_PRIVATE).getInt("theme", 0); } catch (RuntimeException e) { return 0; }
    }
    static int scheme(Context c) {
        try { return c.getSharedPreferences("xnuron", Context.MODE_PRIVATE).getInt("scheme", 0); } catch (RuntimeException e) { return 0; }
    }
    /** Framebuffer of the IPSW attempt (landscape Mac): 0 = 640x400, 1 = 960x600 (default), 2 = 1280x800. Applies to the next start. */
    static int resolution(Context c) {
        try { int r = c.getSharedPreferences("xnuron", Context.MODE_PRIVATE).getInt("res", 1); return r < 0 || r > 2 ? 1 : r; } catch (RuntimeException e) { return 1; }
    }
    static final int[][] RES = { { 640, 400 }, { 960, 600 }, { 1280, 800 } };
    static void save(Context c, String key, Object v) {
        try {
            android.content.SharedPreferences.Editor e = c.getSharedPreferences("xnuron", Context.MODE_PRIVATE).edit();
            if (v instanceof Boolean) e.putBoolean(key, (Boolean) v); else e.putInt(key, (Integer) v);
            e.apply();
        } catch (RuntimeException ignored) { }
    }

    /** The MacNuron Liquid Glass scheme: deep dark-blue / icy graphite in dark mode, light icy in light mode, macOS Blue (#0A84FF / #007AFF), translucent cards with 1dp outline glass stroke. */
    private void brand() {
        if (night) {
            primary = 0xFF0A84FF; onPrimary = 0xFFFFFFFF; primaryContainer = 0xB3162640; onPrimaryContainer = 0xFFEAF2FF;
            surface = 0xFF0B101B; onSurface = 0xFFEAF2FF; onSurfaceVariant = 0xFFA5B8D4;
            container = 0xA6131E32; containerHigh = 0xCC1C2B46; outline = 0x6678B4FF;
        } else {
            primary = 0xFF007AFF; onPrimary = 0xFFFFFFFF; primaryContainer = 0xCCFFFFFF; onPrimaryContainer = 0xFF092040;
            surface = 0xFFEEF4FC; onSurface = 0xFF0D1726; onSurfaceVariant = 0xFF4A5E78;
            container = 0xB3E2EDF9; containerHigh = 0xCCD4E4F7; outline = 0x55007AFF;
        }
    }

    /** Classic: plain neutral grey, white (light) or near-black (dark), no accent colour at all. */
    private void classic() {
        if (night) {
            primary = 0xFFE0E0E0; onPrimary = 0xFF1A1A1A; primaryContainer = 0xFF3A3A3A; onPrimaryContainer = 0xFFEDEDED;
            surface = 0xFF0E0E0E; onSurface = 0xFFE6E6E6; onSurfaceVariant = 0xFFB5B5B5;
            container = 0xFF1B1B1B; containerHigh = 0xFF262626; outline = 0xFF777777;
        } else {
            primary = 0xFF2B2B2B; onPrimary = 0xFFFFFFFF; primaryContainer = 0xFFE6E6E6; onPrimaryContainer = 0xFF1A1A1A;
            surface = 0xFFFFFFFF; onSurface = 0xFF1A1A1A; onSurfaceVariant = 0xFF5F5F5F;
            container = 0xFFF2F2F2; containerHigh = 0xFFE8E8E8; outline = 0xFF8A8A8A;
        }
    }

    private void baseline() {
        if (night) {
            primary = 0xFFD0BCFF; onPrimary = 0xFF381E72; primaryContainer = 0xFF4F378B; onPrimaryContainer = 0xFFEADDFF;
            surface = 0xFF141218; onSurface = 0xFFE6E0E9; onSurfaceVariant = 0xFFCAC4D0;
            container = 0xFF211F26; containerHigh = 0xFF2B2930; outline = 0xFF938F99;
        } else {
            primary = 0xFF6750A4; onPrimary = 0xFFFFFFFF; primaryContainer = 0xFFEADDFF; onPrimaryContainer = 0xFF21005D;
            surface = 0xFFFEF7FF; onSurface = 0xFF1D1B20; onSurfaceVariant = 0xFF49454F;
            container = 0xFFF3EDF7; containerHigh = 0xFFECE6F0; outline = 0xFF79747E;
        }
    }

    @android.annotation.TargetApi(31)
    private void dynamic(Context c) {
        if (night) {
            primary = c.getColor(android.R.color.system_accent1_200); onPrimary = c.getColor(android.R.color.system_accent1_800);
            primaryContainer = c.getColor(android.R.color.system_accent1_700); onPrimaryContainer = c.getColor(android.R.color.system_accent1_100);
            surface = c.getColor(android.R.color.system_neutral1_900); onSurface = c.getColor(android.R.color.system_neutral1_100);
            onSurfaceVariant = c.getColor(android.R.color.system_neutral2_200);
            container = c.getColor(android.R.color.system_neutral1_800); containerHigh = c.getColor(android.R.color.system_neutral1_700);
            outline = c.getColor(android.R.color.system_neutral2_400);
        } else {
            primary = c.getColor(android.R.color.system_accent1_600); onPrimary = c.getColor(android.R.color.system_accent1_0);
            primaryContainer = c.getColor(android.R.color.system_accent1_100); onPrimaryContainer = c.getColor(android.R.color.system_accent1_900);
            surface = c.getColor(android.R.color.system_neutral1_10); onSurface = c.getColor(android.R.color.system_neutral1_900);
            onSurfaceVariant = c.getColor(android.R.color.system_neutral2_700);
            container = c.getColor(android.R.color.system_neutral1_50); containerHigh = c.getColor(android.R.color.system_neutral1_100);
            outline = c.getColor(android.R.color.system_neutral2_500);
        }
    }

    int dp(float v) { return Math.round(v * d); }

    GradientDrawable shape(int color, float radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusDp * d);
        if (color == primaryContainer || color == container || color == containerHigh) {
            int alpha = Color.alpha(outline) < 0xFF ? Color.alpha(outline) : (night ? 0x66 : 0x55);
            g.setStroke(Math.max(1, dp(1)), withAlpha(outline, alpha));
        }
        return g;
    }

    void systemBars(Activity a) {
        a.getWindow().setStatusBarColor(surface);
        a.getWindow().setNavigationBarColor(surface);
        int f = a.getWindow().getDecorView().getSystemUiVisibility();
        if (!night) {
            f |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
            if (Build.VERSION.SDK_INT >= 26) f |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        a.getWindow().getDecorView().setSystemUiVisibility(f);
    }

    TextView text(Context c, float sp, int color, boolean medium) {
        TextView t = new TextView(c);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setTypeface(Typeface.create(medium ? "sans-serif-medium" : "sans-serif", Typeface.NORMAL));
        return t;
    }

    /** Pill button, no shadow, ripple in the content colour. */
    Button pill(Context c, String label, int bg, int fg, float heightDp, float sp) {
        Button b = new Button(c);
        b.setAllCaps(false);
        b.setText(label);
        b.setTextSize(sp);
        b.setTextColor(fg);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setGravity(Gravity.CENTER);
        b.setMinHeight(0); b.setMinimumHeight(dp(heightDp));
        b.setMinWidth(0); b.setMinimumWidth(0);
        b.setPadding(dp(20), 0, dp(20), 0);
        if (Build.VERSION.SDK_INT >= 21) b.setStateListAnimator(null);
        style(b, bg, fg);
        return b;
    }

    void style(Button b, int bg, int fg) {
        GradientDrawable g = shape(bg, 60);
        b.setBackground(new RippleDrawable(ColorStateList.valueOf((fg & 0x00FFFFFF) | 0x33000000), g, null));
        b.setTextColor(fg);
    }

    static int withAlpha(int c, int a) { return Color.argb(a, Color.red(c), Color.green(c), Color.blue(c)); }
}
