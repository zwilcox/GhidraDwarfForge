package ghidradwarfforge.output;

import docking.widgets.filechooser.GhidraFileChooser;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/** Modeless view of captured export evidence. Saving is explicit and never replaces a file. */
public final class CoverageReportGui {
    public static final String TITLE = "GhidraDwarfForge export coverage";
    public static final String COMPARISON_TITLE = "GhidraDwarfForge coverage comparison";
    private CoverageReportGui() { }

    public static void show(Window owner, CoverageReportClaims claims, String status,
            String report, Path suggestedPath) {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("coverage view must be opened on the event thread");
        }
        var dialog = new JDialog(owner, TITLE, java.awt.Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        var closed = new AtomicBoolean();
        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent event) { closed.set(true); }
            @Override public void windowClosed(WindowEvent event) { closed.set(true); }
        });
        var summary = area(CoveragePresentation.summary(claims, status), "coverage-summary");
        var details = area("Select a function to inspect its evidence.", "coverage-details");
        var functions = claims.coverage().functions();
        var table = new JTable(new AbstractTableModel() {
            @Override public int getRowCount() { return functions.size(); }
            @Override public int getColumnCount() { return CoveragePresentation.COLUMNS.length; }
            @Override public String getColumnName(int column) { return CoveragePresentation.COLUMNS[column]; }
            @Override public Object getValueAt(int row, int column) {
                return CoveragePresentation.cell(functions.get(row), column);
            }
        });
        table.setName("coverage-functions");
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        var renderer = new DefaultTableCellRenderer();
        renderer.putClientProperty("html.disable", Boolean.TRUE);
        table.setDefaultRenderer(Object.class, renderer);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                details.setText(CoveragePresentation.details(functions.get(
                    table.convertRowIndexToModel(table.getSelectedRow()))));
                details.setCaretPosition(0);
            }
        });
        var rows = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), new JScrollPane(details));
        rows.setResizeWeight(0.55);
        var content = new JPanel(new BorderLayout(8, 8));
        var summaryScroll = new JScrollPane(summary);
        summaryScroll.setPreferredSize(new Dimension(1000, 175));
        content.add(summaryScroll, BorderLayout.NORTH);
        content.add(rows, BorderLayout.CENTER);
        var controls = new JPanel(new BorderLayout(8, 8));
        var saveStatus = area("Save the complete JSON report to a new filename.", "coverage-save-status");
        controls.add(saveStatus, BorderLayout.CENTER);
        var buttons = new JPanel();
        var save = new JButton("Save report...");
        save.addActionListener(event -> {
            var chooser = new GhidraFileChooser(dialog);
            java.io.File selected;
            try {
                chooser.setTitle("Save coverage report");
                chooser.setApproveButtonText("Save");
                chooser.setSelectedFile(suggestedPath.toFile());
                selected = chooser.getSelectedFile();
            }
            finally { chooser.dispose(); }
            if (selected == null || closed.get()) return;
            save.setEnabled(false);
            saveStatus.setText("Saving complete report...");
            new SwingWorker<Path, Void>() {
                @Override protected Path doInBackground() throws Exception {
                    return ReportFileSave.writeNew(selected.toPath(), report, closed::get);
                }
                @Override protected void done() {
                    if (closed.get() || !dialog.isDisplayable()) return;
                    save.setEnabled(true);
                    try { saveStatus.setText("Report saved: " + get()); }
                    catch (Exception failure) {
                        Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                        saveStatus.setText("Report save failed: " + cause.getMessage());
                    }
                }
            }.execute();
        });
        buttons.add(save);
        var compare = new JButton("Compare report...");
        var cancelComparison = new JButton("Cancel comparison");
        cancelComparison.setEnabled(false);
        var comparisonCancelled = new AtomicBoolean();
        cancelComparison.addActionListener(event -> {
            comparisonCancelled.set(true);
            saveStatus.setText("Cancelling comparison...");
        });
        compare.addActionListener(event -> {
            var chooser = new GhidraFileChooser(dialog);
            java.io.File selected;
            try {
                chooser.setTitle("Select earlier coverage report");
                chooser.setApproveButtonText("Compare");
                chooser.setSelectedFile(suggestedPath.toFile());
                selected = chooser.getSelectedFile();
            }
            finally { chooser.dispose(); }
            if (selected == null || closed.get()) return;
            comparisonCancelled.set(false);
            compare.setEnabled(false);
            cancelComparison.setEnabled(true);
            saveStatus.setText("Comparing selected earlier report with this export...");
            new SwingWorker<String, Void>() {
                @Override protected String doInBackground() throws Exception {
                    return CoverageComparisonPresentation.compare(report, selected.toPath(),
                        () -> closed.get() || comparisonCancelled.get());
                }
                @Override protected void done() {
                    if (closed.get() || !dialog.isDisplayable()) return;
                    compare.setEnabled(true);
                    cancelComparison.setEnabled(false);
                    try {
                        String text = get();
                        if (comparisonCancelled.get()) {
                            saveStatus.setText("Comparison cancelled; no complete result is shown.");
                            return;
                        }
                        saveStatus.setText("Comparison finished. Selected earlier report: " + selected);
                        showComparison(dialog, text);
                    }
                    catch (Exception failure) {
                        Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                        saveStatus.setText(cause instanceof java.util.concurrent.CancellationException
                            ? "Comparison cancelled; no complete result is shown."
                            : "Comparison failed: " + cause.getMessage());
                    }
                }
            }.execute();
        });
        buttons.add(compare);
        buttons.add(cancelComparison);
        var close = new JButton("Close");
        close.addActionListener(event -> { closed.set(true); dialog.dispose(); });
        buttons.add(close);
        controls.add(buttons, BorderLayout.EAST);
        content.add(controls, BorderLayout.SOUTH);
        dialog.setContentPane(content);
        dialog.getRootPane().setDefaultButton(close);
        dialog.setSize(1150, 750);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
        if (!functions.isEmpty()) table.setRowSelectionInterval(0, 0);
    }

    private static void showComparison(Window owner, String text) {
        var dialog = new JDialog(owner, COMPARISON_TITLE, java.awt.Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        var content = new JPanel(new BorderLayout(8, 8));
        content.add(new JScrollPane(area(text, "coverage-comparison-result")), BorderLayout.CENTER);
        var close = new JButton("Close comparison");
        close.addActionListener(event -> dialog.dispose());
        content.add(close, BorderLayout.SOUTH);
        dialog.setContentPane(content);
        dialog.getRootPane().setDefaultButton(close);
        dialog.setSize(1050, 650);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private static JTextArea area(String text, String name) {
        var area = new JTextArea(text);
        area.setName(name);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }
}
