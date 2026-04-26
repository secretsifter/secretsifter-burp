package com.secretscanner;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Custom iOS-style toggle switch.
 *
 * Extends JComponent directly so no Swing L&F UI delegate can override
 * the rendering. Selection state, mouse handling, and action dispatch are
 * all implemented manually — the public API mirrors the subset of
 * AbstractButton used by SettingsPanel and BulkScanPanel:
 *   isSelected(), setSelected(boolean), addActionListener(ActionListener)
 */
class ToggleSwitch extends JComponent {

    private static final int TRACK_W = 28;
    private static final int TRACK_H = 13;
    private static final int THUMB_D = 9;
    private static final int GAP     = 4;

    private static final Color ON_COLOR  = new Color(52, 168, 83);
    private static final Color OFF_COLOR = new Color(190, 190, 190);

    private volatile boolean selected;
    private final String     text;
    private final List<ActionListener> actionListeners = new CopyOnWriteArrayList<>();

    ToggleSwitch(String text, boolean selected) {
        this.text     = text;
        this.selected = selected;
        setOpaque(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder(1, 0, 1, 3));
        setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));

        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (isEnabled()) {
                    ToggleSwitch.this.selected = !ToggleSwitch.this.selected;
                    repaint();
                    ActionEvent ae = new ActionEvent(
                            ToggleSwitch.this,
                            ActionEvent.ACTION_PERFORMED, "toggle");
                    for (ActionListener l : actionListeners) l.actionPerformed(ae);
                }
            }
        });
    }

    boolean isSelected()           { return selected; }
    void    setSelected(boolean b) { if (selected != b) { selected = b; repaint(); } }

    void addActionListener(ActionListener l)    { if (l != null) actionListeners.add(l); }
    void removeActionListener(ActionListener l) { actionListeners.remove(l); }

    @Override
    public Dimension getPreferredSize() {
        Font f = getFont() != null ? getFont() : new Font(Font.SANS_SERIF, Font.PLAIN, 12);
        FontMetrics fm = getFontMetrics(f);
        int textW = (text != null && !text.isEmpty()) ? fm.stringWidth(text) + GAP : 0;
        Insets ins = getInsets();
        int w = TRACK_W + textW + ins.left + ins.right;
        int h = Math.max(TRACK_H + ins.top + ins.bottom,
                         fm.getHeight() + ins.top + ins.bottom + 4);
        return new Dimension(w, h);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,      RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        Insets ins    = getInsets();
        int    h      = getHeight();
        int    trackY = (h - TRACK_H) / 2;

        // Track
        g2.setColor(selected ? ON_COLOR : OFF_COLOR);
        g2.fillRoundRect(ins.left, trackY, TRACK_W, TRACK_H, TRACK_H, TRACK_H);

        // Thumb
        int thumbX = ins.left + (selected ? TRACK_W - THUMB_D - 2 : 2);
        int thumbY = trackY + (TRACK_H - THUMB_D) / 2;
        g2.setColor(Color.WHITE);
        g2.fillOval(thumbX, thumbY, THUMB_D, THUMB_D);

        // Label text
        if (text != null && !text.isEmpty()) {
            Font f = getFont() != null ? getFont() : new Font(Font.SANS_SERIF, Font.PLAIN, 12);
            g2.setFont(f);
            FontMetrics fm = g2.getFontMetrics();
            g2.setColor(isEnabled() ? getForeground() : Color.GRAY);
            int textX = ins.left + TRACK_W + GAP;
            int textY = (h - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(text, textX, textY);
        }

        g2.dispose();
    }
}
