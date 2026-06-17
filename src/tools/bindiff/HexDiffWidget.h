#ifndef HEXDIFFWIDGET_H
#define HEXDIFFWIDGET_H

#include "widgets/Dashboard.h"
#include "HexDiff.h"
#include "widgets/MemoryDockWidget.h"
#include "common/CutterSeekable.h"

#include <QAction>
#include <QDebug>
#include <QMouseEvent>
#include <QTextEdit>

#include <memory>

namespace Ui {
class HexDiffWidget;
}

class RefreshDeferrer;
class QSyntaxHighlighter;

/**
 * @brief Hex dump widget containing a side panel for data parsing and hashing
 *
 * @see HexDiff
 */
class HexDiffWidget : public MemoryDockWidget
{
    Q_OBJECT
public:
    explicit HexDiffWidget(MainWindow *main);
    ~HexDiffWidget() override;

    static QString getWidgetType();

public slots:
    void initParsing();

protected:
    virtual void resizeEvent(QResizeEvent *event) override;
    QWidget *widgetToFocusOnRaise() override;

private:
    std::unique_ptr<Ui::HexDiffWidget> ui;

    bool sentSeek = false;

    RefreshDeferrer *refreshDeferrer;
    QSyntaxHighlighter *syntaxHighLighter;

    void refresh();
    void refresh(RVA addr);
    void selectHexPreview();

    void setupFonts();

    void refreshSelectionInfo();
    void updateParseWindow(RVA start_address, int size);
    void clearParseWindow();
    void showSidePanel(bool show);

    QString getWindowTitle() const override;

private slots:
    void onSeekChanged(RVA addr);

    void selectionChanged(HexDiff::Selection selection);

    void onParseArchComboBoxCurrentTextChanged(const QString &arg1);
    void onParseBitsComboBoxCurrentTextChanged(const QString &arg1);
    void onParseTypeComboBoxCurrentTextChanged(const QString &arg1);
    void onParseEndianComboBoxCurrentTextChanged(const QString &arg1);

    void fontsUpdated();

    void onHexSideTab2CurrentChanged(int index);
    void onCopyMD5Clicked();
    void onCopyShA1Clicked();
    void onCopyShA256Clicked();
    void onCopyCrC32Clicked();
};

#endif // HEXDIFFWIDGET_H
