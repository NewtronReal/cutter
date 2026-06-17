#include "HexDiffWidget.h"

#include "common/Configuration.h"
#include "common/Helpers.h"
#include "common/TempConfig.h"
#include "core/MainWindow.h"
#include "ui_HexDiffWidget.h"

#include <QClipboard>
#include <QElapsedTimer>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QMenu>
#include <QScrollBar>
#include <QShortcut>
#include <QTextDocumentFragment>

HexDiffWidget::HexDiffWidget(MainWindow *main)
    : MemoryDockWidget(MemoryWidgetType::Hexdump, main), ui(new Ui::HexDiffWidget)
{
    ui->setupUi(this);

    setObjectName(main ? main->getUniqueObjectName(getWidgetType()) : getWidgetType());
    updateWindowTitle();

    ui->copyMD5->setIcon(QIcon(":/img/icons/copy.svg"));
    ui->copySHA1->setIcon(QIcon(":/img/icons/copy.svg"));
    ui->copySHA256->setIcon(QIcon(":/img/icons/copy.svg"));
    ui->copyCRC32->setIcon(QIcon(":/img/icons/copy.svg"));


    ui->splitter->setChildrenCollapsible(false);

    auto *closeButton = new QToolButton;
    const QIcon closeIcon = QIcon(":/img/icons/delete.svg");
    closeButton->setIcon(closeIcon);
    closeButton->setAutoRaise(true);

    ui->hexSideTab2->setCornerWidget(closeButton);
    syntaxHighLighter = Config()->createSyntaxHighlighter(ui->hexDisasTextEdit->document());

    ui->openSideViewB->hide(); // hide button at startup since side view is visible

    connect(closeButton, &QToolButton::clicked, this, [this] { showSidePanel(false); });

    connect(ui->openSideViewB, &QToolButton::clicked, this, [this] { showSidePanel(true); });

    // Set placeholders for the line-edit components
    const QString placeholder = tr("Select bytes to display information");
    ui->bytesMD5->setPlaceholderText(placeholder);
    ui->bytesEntropy->setPlaceholderText(placeholder);
    ui->bytesSHA1->setPlaceholderText(placeholder);
    ui->bytesSHA256->setPlaceholderText(placeholder);
    ui->bytesCRC32->setPlaceholderText(placeholder);
    ui->hexDisasTextEdit->setPlaceholderText(placeholder);

    setupFonts();

    ui->openSideViewB->setStyleSheet(""
                                     "QToolButton {"
                                     "   border : 0px;"
                                     "   padding : 0px;"
                                     "   margin : 0px;"
                                     "}"
                                     "QToolButton:hover {"
                                     "  border : 1px solid;"
                                     "  border-width : 1px;"
                                     "  border-color : #3daee9"
                                     "}");

    refreshDeferrer = createReplacingRefreshDeferrer<RVA>(
            false, [this](const RVA *offset) { refresh(offset ? *offset : RVA_INVALID); });

    this->ui->hexDiffView->addAction(&syncAction);

    connect(Config(), &Configuration::fontsUpdated, this, &HexDiffWidget::fontsUpdated);
    connect(Core(), &CutterCore::refreshAll, this, [this]() { refresh(); });
    connect(Core(), &CutterCore::refreshCodeViews, this, [this]() { refresh(); });
    connect(Core(), &CutterCore::instructionChanged, this, [this]() { refresh(); });
    connect(Core(), &CutterCore::stackChanged, this, [this]() { refresh(); });
    connect(Core(), &CutterCore::registersChanged, this, [this]() { refresh(); });

    connect(seekable, &CutterSeekable::seekableSeekChanged, this, &HexDiffWidget::onSeekChanged);
    connect(ui->hexDiffView, &HexDiff::positionChanged, this, [this](RVA addr) {
        if (!sentSeek) {
            sentSeek = true;
            seekable->seek(addr);
            sentSeek = false;
        }
    });

    connect(ui->hexDiffView, &HexDiff::selectionChanged, this, &HexDiffWidget::selectionChanged);
    connect(ui->hexSideTab2, &QTabWidget::currentChanged, this,
            &HexDiffWidget::refreshSelectionInfo);
    ui->hexDiffView->installEventFilter(this);

    // transpose
    connect(ui->transAUp, &QPushButton::clicked, this, [this]{
        ui->hexDiffView->transpose(1,0);
    });
    connect(ui->transADown, &QPushButton::clicked, this, [this]{
        ui->hexDiffView->transpose(-1,0);
    });
    connect(ui->transBUp, &QPushButton::clicked, this, [this]{
        ui->hexDiffView->transpose(0,1);
    });
    connect(ui->transBDown, &QPushButton::clicked, this, [this]{
        ui->hexDiffView->transpose(0,-1);
    });

    initParsing();
    selectHexPreview();

    connect(ui->parseTypeComboBox, &QComboBox::currentTextChanged, this,
            &HexDiffWidget::onParseTypeComboBoxCurrentTextChanged);
    connect(ui->parseArchComboBox, &QComboBox::currentTextChanged, this,
            &HexDiffWidget::onParseArchComboBoxCurrentTextChanged);
    connect(ui->parseBitsComboBox, &QComboBox::currentTextChanged, this,
            &HexDiffWidget::onParseBitsComboBoxCurrentTextChanged);
    connect(ui->parseEndianComboBox, &QComboBox::currentTextChanged, this,
            &HexDiffWidget::onParseEndianComboBoxCurrentTextChanged);
    connect(ui->hexSideTab2, &QTabWidget::currentChanged, this,
            &HexDiffWidget::onHexSideTab2CurrentChanged);

    connect(ui->copyMD5, &QToolButton::clicked, this, &HexDiffWidget::onCopyMD5Clicked);
    connect(ui->copySHA1, &QToolButton::clicked, this, &HexDiffWidget::onCopyShA1Clicked);
    connect(ui->copySHA256, &QToolButton::clicked, this, &HexDiffWidget::onCopyShA256Clicked);
    connect(ui->copyCRC32, &QToolButton::clicked, this, &HexDiffWidget::onCopyCrC32Clicked);

    // apply initial offset
    refresh(seekable->getOffset());
}

void HexDiffWidget::onSeekChanged(RVA addr)
{
    if (sentSeek) {
        sentSeek = false;
        return;
    }
    refresh(addr);
}

HexDiffWidget::~HexDiffWidget() {}

QString HexDiffWidget::getWidgetType()
{
    return "Hexdump";
}

void HexDiffWidget::refresh()
{
    refresh(RVA_INVALID);
}

void HexDiffWidget::refresh(RVA addr)
{
    if (!refreshDeferrer->attemptRefresh(addr == RVA_INVALID ? nullptr : new RVA(addr))) {
        return;
    }
    sentSeek = true;
    if (addr != RVA_INVALID) {
        ui->hexDiffView->seek(addr);
    } else {
        ui->hexDiffView->refresh();
        refreshSelectionInfo();
    }
    sentSeek = false;
}

void HexDiffWidget::initParsing()
{
    // Fill the plugins combo for the hexdump sidebar
    ui->parseTypeComboBox->addItem(tr("Disassembly"), "pda");
    ui->parseTypeComboBox->addItem(tr("String"), "pcs");
    ui->parseTypeComboBox->addItem(tr("Assembler"), "pca");
    ui->parseTypeComboBox->addItem(tr("C bytes"), "pc");
    ui->parseTypeComboBox->addItem(tr("C half-words (2 byte)"), "pch");
    ui->parseTypeComboBox->addItem(tr("C words (4 byte)"), "pcw");
    ui->parseTypeComboBox->addItem(tr("C dwords (8 byte)"), "pcd");
    ui->parseTypeComboBox->addItem(tr("Python"), "pcp");
    ui->parseTypeComboBox->addItem(tr("JSON"), "pcj");
    ui->parseTypeComboBox->addItem(tr("JavaScript"), "pcJ");
    ui->parseTypeComboBox->addItem(tr("Yara"), "pcy");

    ui->parseArchComboBox->insertItems(0, Core()->getAsmPluginNames());

    ui->parseEndianComboBox->setCurrentIndex(Core()->getConfigb("cfg.bigendian") ? 1 : 0);
}

void HexDiffWidget::selectionChanged(HexDiff::Selection selection)
{
    if (selection.empty) {
        clearParseWindow();
    } else {
        updateParseWindow(selection.startAddress,
                          selection.endAddress - selection.startAddress + 1);
    }
}

void HexDiffWidget::onParseArchComboBoxCurrentTextChanged(const QString & /*arg1*/)
{
    refreshSelectionInfo();
}

void HexDiffWidget::onParseBitsComboBoxCurrentTextChanged(const QString & /*arg1*/)
{
    refreshSelectionInfo();
}

void HexDiffWidget::setupFonts()
{
    const QFont font = Config()->getFont();
    ui->hexDisasTextEdit->setFont(font);
    ui->hexDiffView->setMonospaceFont(font);
}

void HexDiffWidget::refreshSelectionInfo()
{
    selectionChanged(ui->hexDiffView->getSelection());
}

void HexDiffWidget::fontsUpdated()
{
    setupFonts();
}

void HexDiffWidget::clearParseWindow()
{
    ui->hexDisasTextEdit->setPlainText("");
    ui->bytesEntropy->setText("");
    ui->bytesMD5->setText("");
    ui->bytesSHA1->setText("");
    ui->bytesSHA256->setText("");
    ui->bytesCRC32->setText("");
}

void HexDiffWidget::showSidePanel(bool show)
{
    ui->hexSideTab2->setVisible(show);
    ui->openSideViewB->setHidden(show);
    if (show) {
        refreshSelectionInfo();
    }
}

QString HexDiffWidget::getWindowTitle() const
{
    return tr("Hexdump");
}

void HexDiffWidget::updateParseWindow(RVA start_address, int size)
{
    if (!ui->hexSideTab2->isVisible()) {
        return;
    }

    if (ui->hexSideTab2->currentIndex() == 1) {
        // scope for TempConfig

        // Get selected combos
        const QString arch = ui->parseArchComboBox->currentText();
        const QString bits = ui->parseBitsComboBox->currentText();
        const QString selectedCommand = ui->parseTypeComboBox->currentData().toString();
        const QString commandResult = "";
        const bool bigEndian = ui->parseEndianComboBox->currentIndex() == 1;

        TempConfig tempConfig;
        tempConfig.set("asm.arch", arch).set("asm.bits", bits).set("cfg.bigendian", bigEndian);

        ui->hexDisasTextEdit->setPlainText(
                selectedCommand != ""
                        ? Core()->cmdRawAt(QString("%1 @! %2").arg(selectedCommand).arg(size),
                                           start_address)
                        : "");
    } else if(ui->hexSideTab2->currentIndex() == 2) {
        // Fill the information tab hashes and entropy
        RzHashSize digestSize = 0;
        RzCoreLocked core(Core());
        const ut64 oldOffset = core->offset;
        rz_core_seek(core, start_address, true);
        const ut8 *block = core->block;
        char *digest = rz_hash_cfg_calculate_small_block_string(core->hash, "md5", block, size,
                                                                &digestSize, false);
        ui->bytesMD5->setText(QString(digest));
        free(digest);
        digest = rz_hash_cfg_calculate_small_block_string(core->hash, "sha1", block, size,
                                                          &digestSize, false);
        ui->bytesSHA1->setText(QString(digest));
        free(digest);
        digest = rz_hash_cfg_calculate_small_block_string(core->hash, "sha256", block, size,
                                                          &digestSize, false);
        ui->bytesSHA256->setText(QString(digest));
        free(digest);
        digest = rz_hash_cfg_calculate_small_block_string(core->hash, "crc32", block, size,
                                                          &digestSize, false);
        ui->bytesCRC32->setText(QString(digest));
        free(digest);
        digest = rz_hash_cfg_calculate_small_block_string(core->hash, "entropy", block, size,
                                                          &digestSize, false);
        ui->bytesEntropy->setText(QString(digest));
        free(digest);
        rz_core_seek(core, oldOffset, true);
        ui->bytesMD5->setCursorPosition(0);
        ui->bytesSHA1->setCursorPosition(0);
        ui->bytesSHA256->setCursorPosition(0);
        ui->bytesCRC32->setCursorPosition(0);
    }
}

void HexDiffWidget::onParseTypeComboBoxCurrentTextChanged(const QString &)
{
    const QString currentParseTypeText = ui->parseTypeComboBox->currentData().toString();
    if (currentParseTypeText == "pda" || currentParseTypeText == "pci") {
        ui->hexSideFrame2->show();
    } else {
        ui->hexSideFrame2->hide();
    }
    refreshSelectionInfo();
}

void HexDiffWidget::onParseEndianComboBoxCurrentTextChanged(const QString &)
{
    refreshSelectionInfo();
}

void HexDiffWidget::onHexSideTab2CurrentChanged(int /*index*/)
{
    /*
    if (index == 2) {
        // Add data to HTML Polar functions graph
        QFile html(":/html/bar.html");
        if(!html.open(QIODevice::ReadOnly)) {
            QMessageBox::information(0,"error",html.errorString());
        }
        QString code = html.readAll();
        html.close();
        this->histoWebView->setHtml(code);
        this->histoWebView->show();
    } else {
        this->histoWebView->hide();
    }
    */
}

void HexDiffWidget::resizeEvent(QResizeEvent *event)
{
    // Heuristics to hide sidebar when it hides the content of the hexdump. 600px looks just "okay"
    // Only applied when widget width is decreased to avoid unwanted behavior
    if (event->oldSize().width() > event->size().width() && event->size().width() < 600) {
        showSidePanel(false);
    }
    QDockWidget::resizeEvent(event);
    refresh();
}

QWidget *HexDiffWidget::widgetToFocusOnRaise()
{
    return ui->hexDiffView;
}

void HexDiffWidget::onCopyMD5Clicked()
{
    const QString md5 = ui->bytesMD5->text();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(md5);
    Core()->message("MD5 copied to clipboard: " + md5);
}

void HexDiffWidget::onCopyShA1Clicked()
{
    const QString sha1 = ui->bytesSHA1->text();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(sha1);
    Core()->message("SHA1 copied to clipboard: " + sha1);
}

void HexDiffWidget::onCopyShA256Clicked()
{
    const QString sha256 = ui->bytesSHA256->text();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(sha256);
    Core()->message("SHA256 copied to clipboard: " + sha256);
}

void HexDiffWidget::onCopyCrC32Clicked()
{
    const QString crc32 = ui->bytesCRC32->text();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(crc32);
    Core()->message("CRC32 copied to clipboard: " + crc32);
}

void HexDiffWidget::selectHexPreview()
{
    // Pre-select arch and bits in the hexdump sidebar
    const QString arch = Core()->getConfig("asm.arch");
    const QString bits = Core()->getConfig("asm.bits");

    if (ui->parseArchComboBox->findText(arch) != -1) {
        ui->parseArchComboBox->setCurrentIndex(ui->parseArchComboBox->findText(arch));
    }

    if (ui->parseBitsComboBox->findText(bits) != -1) {
        ui->parseBitsComboBox->setCurrentIndex(ui->parseBitsComboBox->findText(bits));
    }
}
