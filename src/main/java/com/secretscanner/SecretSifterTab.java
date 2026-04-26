package com.secretscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Adds a "SecretSifter" tab to Burp's HTTP message editor (HTTP History,
 * Proxy, Repeater).  When the analyst selects a request/response, the tab
 * displays a table of findings for that response — rule ID, severity,
 * confidence, key/field, matched value, and line number.
 *
 * Findings are produced on demand by re-running the scanner on the response
 * body.  A lightweight hash avoids redundant re-scans when the analyst clicks
 * between Pretty/Raw/Hex tabs on the same response.
 *
 * Tab-level features:
 *   - Severity dropdown — double-click the Severity cell to override per finding
 *   - Export CSV / Export HTML — saves visible (post-removal) findings to disk
 *   - Remove Selected — deletes noise findings from this tab view only;
 *     does not affect Burp's Dashboard / sitemap issues
 */
public class SecretSifterTab implements HttpResponseEditorProvider {

    private final SecretScanner scanner;

    public SecretSifterTab(SecretScanner scanner) {
        this.scanner = scanner;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(
            EditorCreationContext creationContext) {
        return new FindingsEditor(scanner);
    }

    // -------------------------------------------------------------------------

    private static class FindingsEditor implements ExtensionProvidedHttpResponseEditor {

        private final SecretScanner scanner;
        private final JPanel        panel;
        private final FindingsModel model;
        private final JTable        table;
        private final JLabel        statusLabel;

        // Last-response cache — avoids re-scanning on tab switches
        private String       lastHash     = "";
        private HttpResponse lastResponse = null;

        FindingsEditor(SecretScanner scanner) {
            this.scanner = scanner;

            model = new FindingsModel();
            table = new JTable(model);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            table.setRowHeight(18);
            table.setShowGrid(true);
            table.setGridColor(new Color(220, 220, 220));
            table.getTableHeader().setReorderingAllowed(false);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

            // Column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
            table.getColumnModel().getColumn(1).setPreferredWidth(80);   // Severity
            table.getColumnModel().getColumn(2).setPreferredWidth(70);   // Confidence
            table.getColumnModel().getColumn(3).setPreferredWidth(160);  // Rule ID
            table.getColumnModel().getColumn(4).setPreferredWidth(140);  // Key / Field
            table.getColumnModel().getColumn(5).setPreferredWidth(280);  // Matched Value
            table.getColumnModel().getColumn(6).setPreferredWidth(50);   // Line

            table.getColumnModel().getColumn(1).setCellRenderer(new SeverityRenderer());

            // Severity dropdown editor — double-click a Severity cell to change it
            JComboBox<String> sevCombo = new JComboBox<>(
                    new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"});
            table.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(sevCombo));

            // Right-click: select the row under the cursor, then show popup
            JPopupMenu popup = new JPopupMenu();
            JMenuItem removeItem = new JMenuItem("Remove Finding(s)");
            popup.add(removeItem);
            removeItem.addActionListener(e -> removeSelected());

            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        int row = table.rowAtPoint(e.getPoint());
                        if (row >= 0 && !table.isRowSelected(row))
                            table.setRowSelectionInterval(row, row);
                        popup.show(table, e.getX(), e.getY());
                    }
                }
            });

            // Toolbar
            JButton exportCsvBtn  = new JButton("Export CSV");
            JButton exportHtmlBtn = new JButton("Export HTML");
            JButton removeBtn     = new JButton("Remove Selected");
            exportCsvBtn.addActionListener(e  -> exportCsv());
            exportHtmlBtn.addActionListener(e -> exportHtml());
            removeBtn.addActionListener(e     -> removeSelected());

            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            toolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 0));
            toolbar.add(exportCsvBtn);
            toolbar.add(exportHtmlBtn);
            toolbar.add(removeBtn);

            statusLabel = new JLabel("Select a response to scan.");
            statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
            statusLabel.setForeground(Color.GRAY);
            statusLabel.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));

            panel = new JPanel(new BorderLayout(0, 4));
            panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
            panel.add(toolbar, BorderLayout.NORTH);
            panel.add(new JScrollPane(table), BorderLayout.CENTER);
            panel.add(statusLabel, BorderLayout.SOUTH);
        }

        // ---- actions ----

        private void removeSelected() {
            // Stop any in-progress cell edit so the model is consistent
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            int[] sel = table.getSelectedRows();
            if (sel.length == 0) return;
            model.removeRows(sel);
            refreshStatus();
        }

        private void refreshStatus() {
            int remaining = model.getRowCount();
            if (remaining == 0) {
                statusLabel.setText("No secrets found.");
                statusLabel.setForeground(new Color(0, 130, 0));
            } else {
                boolean hasCustom = model.getFindings().stream()
                        .anyMatch(f -> f.ruleId().startsWith("CUSTOM_"));
                if (hasCustom) {
                    statusLabel.setText(remaining +
                            " finding(s) \u2014 \u26a0 CUSTOM_ rule matches need analyst review.");
                    statusLabel.setForeground(new Color(160, 80, 0));
                } else {
                    statusLabel.setText(remaining + " finding(s).");
                    statusLabel.setForeground(new Color(0, 130, 0));
                }
            }
        }

        private void exportCsv() {
            List<SecretFinding> findings = model.getFindings();
            if (findings.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "No findings to export.",
                        "Export CSV", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Export Findings as CSV");
            fc.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
            fc.setSelectedFile(new File("secretsifter-findings.csv"));
            if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
            File file = fc.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".csv"))
                file = new File(file.getPath() + ".csv");
            try (PrintWriter pw = new PrintWriter(file, StandardCharsets.UTF_8)) {
                pw.println("#,Severity,Confidence,Rule ID,Key / Field,Matched Value,Line,URL");
                int n = 1;
                for (SecretFinding f : findings) {
                    pw.printf("%d,%s,%s,%s,%s,%s,%d,%s%n",
                            n++,
                            csvEscape(f.severity()),
                            csvEscape(f.confidence()),
                            csvEscape(f.ruleId()),
                            csvEscape(f.keyName()),
                            csvEscape(f.matchedValue()),
                            f.lineNumber(),
                            csvEscape(f.sourceUrl()));
                }
                JOptionPane.showMessageDialog(panel,
                        "Exported " + findings.size() + " finding(s) to:\n" + file.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Export failed: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void exportHtml() {
            List<SecretFinding> findings = model.getFindings();
            if (findings.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "No findings to export.",
                        "Export HTML", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Export Findings as HTML");
            fc.setFileFilter(new FileNameExtensionFilter("HTML files (*.html)", "html"));
            fc.setSelectedFile(new File("secretsifter-findings.html"));
            if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
            File file = fc.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".html"))
                file = new File(file.getPath() + ".html");
            try (PrintWriter pw = new PrintWriter(file, StandardCharsets.UTF_8)) {
                pw.println(HtmlReportGenerator.generate(findings, "SecretSifter Tab Export", "FULL"));
                JOptionPane.showMessageDialog(panel,
                        "Exported " + findings.size() + " finding(s) to:\n" + file.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Export failed: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private static String csvEscape(String s) {
            if (s == null) return "";
            if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r"))
                return "\"" + s.replace("\"", "\"\"") + "\"";
            return s;
        }

        // ---- ExtensionProvidedHttpResponseEditor ----

        @Override
        public String caption() {
            return "SecretSifter";
        }

        @Override
        public Component uiComponent() {
            return panel;
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse rr) {
            return rr != null && rr.response() != null;
        }

        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            if (rr == null || rr.response() == null) {
                lastResponse = null;
                SwingUtilities.invokeLater(() -> {
                    model.setFindings(List.of());
                    statusLabel.setText("No response.");
                    statusLabel.setForeground(Color.GRAY);
                });
                return;
            }

            lastResponse = rr.response();

            String body = rr.response().bodyToString();
            String ct   = rr.response().headerValue("Content-Type");
            String url  = rr.request() != null ? rr.request().url() : "";

            // Lightweight hash — skip re-scan if same response
            String hash = url + ":" + body.length() + ":" +
                    (body.length() > 8 ? body.substring(0, 8) : body);
            if (hash.equals(lastHash)) return;
            lastHash = hash;

            Thread t = new Thread(() -> {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Scanning\u2026");
                    statusLabel.setForeground(Color.GRAY);
                });
                List<SecretFinding> findings;
                try {
                    findings = scanner.scanText(body, ct, url);
                } catch (Exception ex) {
                    findings = List.of();
                }
                final List<SecretFinding> result = findings;
                SwingUtilities.invokeLater(() -> {
                    model.setFindings(result);
                    boolean hasCustom = result.stream()
                            .anyMatch(f -> f.ruleId().startsWith("CUSTOM_"));
                    if (result.isEmpty()) {
                        statusLabel.setText("No secrets found.");
                        statusLabel.setForeground(new Color(0, 130, 0));
                    } else if (hasCustom) {
                        statusLabel.setText(result.size() +
                                " finding(s) \u2014 \u26a0 CUSTOM_ rule matches need analyst review.");
                        statusLabel.setForeground(new Color(160, 80, 0));
                    } else {
                        statusLabel.setText(result.size() + " finding(s).");
                        statusLabel.setForeground(new Color(0, 130, 0));
                    }
                });
            }, "SecretSifter-TabScan");
            t.setDaemon(true);
            t.start();
        }

        @Override
        public HttpResponse getResponse() {
            return lastResponse;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Table model
    // -------------------------------------------------------------------------

    private static class FindingsModel extends AbstractTableModel {

        private static final String[] COLS =
                {"#", "Severity", "Confidence", "Rule ID", "Key / Field", "Matched Value", "Line"};

        private final List<SecretFinding> rows = new ArrayList<>();

        void setFindings(List<SecretFinding> findings) {
            rows.clear();
            rows.addAll(findings);
            fireTableDataChanged();
        }

        /** Returns a snapshot of the current (possibly pruned/edited) findings. */
        List<SecretFinding> getFindings() {
            return new ArrayList<>(rows);
        }

        /** Remove rows by view index — indices must be valid at call time. */
        void removeRows(int[] indices) {
            int[] sorted = Arrays.copyOf(indices, indices.length);
            Arrays.sort(sorted);
            // Remove from highest index downward so earlier indices stay valid
            for (int i = sorted.length - 1; i >= 0; i--) {
                if (sorted[i] >= 0 && sorted[i] < rows.size())
                    rows.remove(sorted[i]);
            }
            fireTableDataChanged();
        }

        @Override public int getRowCount()    { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int col) { return COLS[col]; }

        /** Only the Severity column is editable (dropdown). */
        @Override
        public boolean isCellEditable(int row, int col) {
            return col == 1;
        }

        /** Persist severity changes made via the dropdown editor. */
        @Override
        public void setValueAt(Object value, int row, int col) {
            if (col == 1 && row < rows.size() && value != null) {
                rows.set(row, rows.get(row).withSeverity(value.toString()));
                fireTableCellUpdated(row, col);
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            SecretFinding f = rows.get(row);
            return switch (col) {
                case 0 -> row + 1;
                case 1 -> f.severity();
                case 2 -> f.confidence();
                case 3 -> f.ruleId();
                case 4 -> f.keyName();
                case 5 -> f.matchedValue().length() > 100
                        ? f.matchedValue().substring(0, 97) + "\u2026" : f.matchedValue();
                case 6 -> f.lineNumber();
                default -> "";
            };
        }
    }

    // -------------------------------------------------------------------------
    // Severity colour renderer
    // -------------------------------------------------------------------------

    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                String sev = value == null ? "" : value.toString().toUpperCase();
                setBackground(switch (sev) {
                    case "CRITICAL", "HIGH" -> new Color(255, 220, 220);
                    case "MEDIUM"           -> new Color(255, 240, 200);
                    case "LOW"              -> new Color(220, 240, 255);
                    default                 -> new Color(240, 240, 240);
                });
                setForeground(switch (sev) {
                    case "CRITICAL", "HIGH" -> new Color(160, 0, 0);
                    case "MEDIUM"           -> new Color(140, 80, 0);
                    case "LOW"              -> new Color(0, 60, 140);
                    default                 -> Color.DARK_GRAY;
                });
            }
            return this;
        }
    }
}
