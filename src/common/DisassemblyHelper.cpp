#include "DisassemblyHelper.h"
#include "Cutter.h"
#include "rz_types_base.h"

typedef struct mmio_lookup_context
{
    QString selected;
    RVA mmio_address;
} mmio_lookup_context_t;

static bool lookup_mmio_addr_cb(void *user, const ut64 key, const void *value)
{
    mmio_lookup_context_t *ctx = (mmio_lookup_context_t *)user;
    if (ctx->selected == (const char *)value) {
        ctx->mmio_address = key;
        return false;
    }
    return true;
}

DisassemblyTextBlockUserData::DisassemblyTextBlockUserData(const DisassemblyLine &line)
    : line { line }
{
}

DisassemblyTextBlockUserData *DisassemblyHelper::getUserData(const QTextBlock &block)
{
    QTextBlockUserData *userData = block.userData();
    if (!userData) {
        return nullptr;
    }

    return static_cast<DisassemblyTextBlockUserData *>(userData);
}

RVA DisassemblyHelper::getXRefFromWord(RVA offset, const QString &selectedWord)
{
    RVA selectedOffset = Core()->num(selectedWord);
    auto xrefsTo = Core()->getXRefs(offset, true, false);
    for (const auto &xref : xrefsTo) {
        if (xref.from == selectedOffset) {
            return xref.from;
        }
    }
    return RVA_INVALID;
}

bool DisassemblyHelper::isXRefFromComment(RVA offset, const QString &line)
{
    return Core()->getXRefCommentAt(offset).simplified().contains(line.simplified());
}

RVA DisassemblyHelper::readDisassemblyOffset(QTextCursor tc)
{
    auto userData = DisassemblyHelper::getUserData(tc.block());
    if (!userData) {
        return RVA_INVALID;
    }

    return userData->line.offset;
}

RVA DisassemblyHelper::readDisassemblyArrow(QTextCursor tc)
{
    auto userData = getUserData(tc.block());
    if (!userData) {
        return RVA_INVALID;
    }

    return userData->line.arrow;
}

DisassemblyHelper::BracketResult DisassemblyHelper::findBracketRange(const QString &line,
                                                                     int posInLine)
{
    BracketResult res;
    int openBracket = line.lastIndexOf('[', posInLine);
    int closeBracket = line.indexOf(']', posInLine);

    if (openBracket != -1 && closeBracket != -1) {
        bool isInside = true;
        for (int i = openBracket + 1; i < posInLine; ++i) {
            if (line[i] == ']') {
                isInside = false;
                break;
            }
        }
        if (isInside) {
            for (int i = posInLine; i < closeBracket; ++i) {
                if (line[i] == '[') {
                    isInside = false;
                    break;
                }
            }
        }

        if (isInside) {
            res.found = true;
            res.start = openBracket;
            res.length = (closeBracket - openBracket) + 1;
            res.content = line.mid(res.start, res.length);
        }
    }
    return res;
}

DisassemblyHelper::TargetContext DisassemblyHelper::getContextFromCursor(QTextCursor tc)
{
    int originalPos = tc.position();
    tc.select(QTextCursor::WordUnderCursor);
    QString word = tc.selectedText();
    QString line = tc.block().text();
    int lineStart = tc.block().position();
    int posInLine = originalPos - lineStart;

    auto bracketRes = findBracketRange(line, posInLine);
    if (bracketRes.found) {
        tc.setPosition(lineStart + bracketRes.start);
        tc.setPosition(lineStart + bracketRes.start + bracketRes.length, QTextCursor::KeepAnchor);
        word = bracketRes.content;
    }

    TargetContext ctx;
    ctx.word = word;
    ctx.line = line;
    ctx.offset = DisassemblyHelper::readDisassemblyOffset(tc);
    ctx.arrow = DisassemblyHelper::readDisassemblyArrow(tc);
    return ctx;
}

DisassemblyHelper::TargetAction DisassemblyHelper::resolveTarget(const TargetContext &ctx,
                                                                 int filter)
{
    TargetAction res = { RVA_INVALID, TargetType::None };

    // Xref comments need special handling to show preview for each caller offset
    if (filter & TargetFilter::XRefComments) {
        bool showXRefComments = Core()->getConfigb("asm.xrefs");
        if (showXRefComments && isXRefFromComment(ctx.offset, ctx.line)) {
            res.value = getXRefFromWord(ctx.offset, ctx.word);
            res.type = TargetType::XRefComment;
            return res;
        }
    }

    if (filter & TargetFilter::VariableValues) {
        QString inner = ctx.word;
        if (inner.startsWith('[') && inner.endsWith(']')) {
            inner = inner.mid(1, inner.length() - 2);
        }

        if (ctx.offset != RVA_INVALID) {
            auto vars = Core()->getVariables(ctx.offset);
            for (auto &var : vars) {
                if (var.name == inner) {
                    res.value = Core()->math(var.value);
                    res.type = TargetType::VariableValue;
                    return res;
                }
            }
        }
    }

    if (filter & TargetFilter::VariableXrefs) {
        XrefDescription xref = Core()->getFirstXRefForVariable(ctx.word, ctx.offset);
        if (!xref.from_str.isEmpty() || !xref.to_str.isEmpty()) {
            res.value = xref.from;
            res.type = TargetType::VariableXRef;
            return res;
        }
    }

    if (filter & TargetFilter::Types) {
        if (Core()->typeExists(ctx.word)) {
            res.type = TargetType::TypeName;
            return res;
        }
    }

    if (filter & TargetFilter::Arrows) {
        if (ctx.arrow != RVA_INVALID) {
            res.type = TargetType::Arrow;
            res.value = ctx.arrow;
            return res;
        }
    }

    if (!ctx.word.isEmpty()) {
        if (filter & TargetFilter::Registers) {
            const auto reg = Core()->getRegisterRefValue(ctx.word);
            if (!reg.name.isEmpty()) {
                res.type = TargetType::Register;
                res.value = Core()->math(reg.value);
                return res;
            }
        }

        if (filter & TargetFilter::MMIO) {
            mmio_lookup_context_t mmio_ctx;
            mmio_ctx.selected = ctx.word;
            mmio_ctx.mmio_address = RVA_INVALID;
            auto core = Core()->lock();
            RzPlatformTarget *arch_target = core->analysis->arch_target;
            if (arch_target && arch_target->profile) {
                ht_up_foreach(arch_target->profile->registers_mmio, lookup_mmio_addr_cb, &mmio_ctx);
            }
            if (mmio_ctx.mmio_address != RVA_INVALID) {
                res.value = mmio_ctx.mmio_address;
                res.type = TargetType::MMIO;
                return res;
            }
        }

        if (filter & TargetFilter::Memory) {
            QString stripped = ctx.word;
            if (stripped.startsWith('[') && stripped.endsWith(']')) {
                stripped = stripped.mid(1, stripped.length() - 2);
                if (Core()->isValidInputNumValue(stripped)
                    || Core()->isValidInputNumValue(ctx.word)) {
                    res.value = Core()->math(ctx.word);
                    res.type = TargetType::Memory;
                    return res;
                }
            }
        }
    }

    return res;
}

int DisassemblyHelper::getOperandIndex(const QTextCursor &cursor)
{
    QString line = cursor.block().text();
    int col = cursor.positionInBlock();
    int commentPos = line.indexOf(';');
    if (commentPos != -1)
        line = line.left(commentPos);
    bool ib = false;
    int op = 0;
    while (col > 0) {
        if (line[col] == ',' && !ib)
            op++;
        if (line[col] == ']')
            ib = true;
        if (line[col] == '[') {
            if (!ib)
                op = 0;
            ib = false;
        }
        col--;
    }
    return op;
}

QString DisassemblyHelper::normalizeExpression(RVA rva, int operandIndex)
{
    CutterJson aoj = Core()->analyseOperandsAt(rva);

    if (!aoj.valid())
        return "";

    CutterJson inst = aoj.first();
    if (!inst.valid())
        return "";

    CutterJson operands = inst["operands"];
    if (!operands.valid())
        return "";

    int i = 0;
    for (auto it = operands.begin(); it != operands.end(); ++it, ++i) {
        if (i != operandIndex)
            continue;

        CutterJson op = *it;

        if (op["type"].toString() != "mem")
            return "";

        QString expr;

        // base register
        if (op["base"].valid())
            expr += op["base"].toString();

        // index register
        if (op["index"].valid()) {
            QString index = op["index"].toString();
            QString term = index;

            if (op["shift"].valid()) {
                term = QString("(%1 << %2)").arg(index).arg(op["shift"].toUt64());
            } else if (op["scale"].valid()) {
                term = QString("(%1 * %2)").arg(index).arg(op["scale"].toUt64());
            }

            if (!expr.isEmpty())
                expr += " + ";

            expr += term;
        }

        // displacement
        if (op["disp"].valid()) {
            st64 disp = op["disp"].toSt64();

            if (!expr.isEmpty()) {
                if (disp >= 0)
                    expr += QString(" + 0x%1").arg((ut64)disp, 0, 16);
                else
                    expr += QString(" - 0x%1").arg((ut64)(-disp), 0, 16);
            } else {
                expr += QString("0x%1").arg((ut64)disp, 0, 16);
            }
        }

        return expr;
    }

    return "";
}

DisassemblyHelper::Token DisassemblyHelper::getToken(QTextCursor cursor)
{
    cursor.select(QTextCursor::WordUnderCursor);
    DisassemblyHelper::Token token;
    token.ref = false;
    token.type = DisassemblyHelper::TokenType::Undef;
    token.isStack = false;

    QString line = cursor.block().text();

    int blockPos = cursor.block().position();

    int start = cursor.selectionStart() - blockPos;
    int end = cursor.selectionEnd() - blockPos;

    bool started = false, ended = false;
    int tokenStart = start, tokenEnd = end;

    bool inBracket = false;

    QString word = cursor.selectedText();
    auto lock = Core()->lock();
    RVA rva = DisassemblyHelper::readDisassemblyOffset(cursor);
    token.operandIndex = getOperandIndex(cursor);

    // scan left
    token.token = word;
    while (start > 0) {
        QChar c = line[start - 1];
        if (!started && !(c.isLetterOrNumber() || c == '.' || c == '_')) {
            started = true;
            tokenStart = start;
        }
        if (c == ';')
            break;

        if (c == '[') {
            inBracket = true;
            start--;
            break;
        }
        start--;
    }

    bool foundClose = false;
    // scan right
    while (end < line.size()) {
        QChar c = line[end];
        if (!ended && !(c.isLetterOrNumber() || c == '.' || c == '_')) {
            ended = true;
            tokenEnd = end;
        }
        if (c == ';')
            break;

        if (c == ']') {
            end++;
            foundClose = true;
            break;
        }
        end++;
    }

    if (foundClose && inBracket) {
        token.ref = true;
        token.expression = line.mid(start, end - start).trimmed();
        token.exparg = "";
        token.normExp = normalizeExpression(rva, token.operandIndex);
    };

    token.token = line.mid(tokenStart, tokenEnd - tokenStart).trimmed();
    token.offset = rva;

    // varcheck
    QList<VariableDescription> vardesc = Core()->getVariables(rva);
    for (auto v : vardesc) {
        if (v.name == token.token) {
            token.type = TokenType::Variable;
            token.vardesc = v;
            if (token.ref && v.value.startsWith("0x")) {
                token.expression.replace(v.name,
                                         v.value.split(QRegularExpression("[^A-Za-z0-9]+"))[0]);
            }
        }
    }

    // regcheck
    RzReg *reg = Core()->getReg();
    RzRegItem *item = rz_reg_get(reg, token.token.toUtf8().constData(), RZ_REG_TYPE_ANY);

    if (item && item->name) {
        token.points = rz_reg_get_value(reg, item);
        token.type = DisassemblyHelper::TokenType::Register;
        token.regitem = item;
    }

    // stackcheck
    RzRegItem *sp = rz_reg_get(reg, "SP", RZ_REG_TYPE_ANY);

    if (QString(sp->name) == token.token && !token.expression.isEmpty()) {
        ut64 spValue = rz_reg_get_value(reg, sp);

        int ptrSize = lock->analysis->bits / 8;

        QByteArray bytes(ptrSize * 5, 0);
        QString info = "";
        rz_io_pread_at(lock->io, spValue, reinterpret_cast<ut8 *>(bytes.data()), bytes.size());
        for (int i = 0; i < 5; i++) {
            ut64 value = 0;
            memcpy(&value, bytes.data() + i * ptrSize, ptrSize);

            info += QString("[%1] 0x%2<br>").arg(i).arg(value, 0, 16);
        }
        token.stackValues = info;
        token.isStack = true;
        return token;
    }

    // flagcheck
    if (token.type == DisassemblyHelper::TokenType::Undef) {
        RzFlagItem *flag = rz_flag_get(lock->flags, token.token.toUtf8().constData());
        if (flag) {
            token.type = TokenType::Symbol;
            ut64 addr = flag->offset;
            token.points = addr;
            return token;
        }
    }

    // immediate check

    if (token.type == TokenType::Undef && token.token.startsWith("0x")) {
        token.type = TokenType::Immediate;
        token.value = QString(token.token).remove("0x").toULongLong(nullptr, 16);
        return token;
    }

    // symbol check
    auto symbols = Core()->getAllSymbols();
    for (auto &a : symbols) {
        if (a.name == token.token) {
            token.type = TokenType::Symbol;
            token.points = a.vaddr;
            return token;
        }
    }

    return token;
}
