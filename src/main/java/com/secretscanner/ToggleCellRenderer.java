package com.secretscanner;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

/**
 * Renders a Boolean table cell as the same iOS-style {@link ToggleSwitch} used across the tool,
 * instead of the default checkbox. Render-only: a mouse listener on the table flips the model
 * value, so no cell editor is involved.
 */
final class ToggleCellRenderer implements TableCellRenderer {

    private final ToggleSwitch sw = new ToggleSwitch("", false);

    ToggleCellRenderer() {
        sw.setBorder(BorderFactory.createEmptyBorder(1, 8, 1, 0));
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        sw.setSelected(Boolean.TRUE.equals(value));
        sw.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
        sw.setOpaque(true);
        return sw;
    }
}
