package ai.burp.ui;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * Swing 样式辅助 — 不硬编码颜色，让组件自动继承 Burp 原生主题（深色/浅色自适应）。
 */
public final class UIStyle
{
    private UIStyle() {}

    public static void compactButton(AbstractButton button)
    {
        button.setFocusable(false);
        button.setMargin(new Insets(2, 10, 2, 10));
        button.setFont(button.getFont().deriveFont(Font.PLAIN, 12f));
    }

    public static void primaryButton(AbstractButton button)
    {
        compactButton(button);
        button.setFont(button.getFont().deriveFont(Font.BOLD, 12f));
    }

    public static JPanel toolbar()
    {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        panel.setBorder(new EmptyBorder(1, 2, 1, 2));
        panel.setOpaque(false);
        return panel;
    }

    public static JLabel mutedLabel(String text)
    {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.PLAIN, 12f));
        return label;
    }

    public static void table(JTable table)
    {
        table.setRowHeight(24);
        table.setAutoCreateRowSorter(true);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
    }

    public static JScrollPane scroll(Component component)
    {
        return new JScrollPane(component);
    }

    public static void textArea(JTextArea area)
    {
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setBorder(new EmptyBorder(6, 6, 6, 6));
    }
}
