/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef vm_RegExpStatics_inl_h
#define vm_RegExpStatics_inl_h

#include "mozilla/MemoryReporting.h"

#include "vm/RegExpStatics.h"

#include "gc/Marking.h"

#include "jsinferinlines.h"

#include "vm/String-inl.h"

namespace js {

class RegExpStatics
{
    /* The latest RegExp output, set after execution. */
    VectorMatchPairs        matches;
    HeapPtr<JSLinearString> matchesInput;

    /*
     * The previous RegExp input, used to resolve lazy state.
     * A raw RegExpShared cannot be stored because it may be in
     * a different compartment via evalcx().
     */
    HeapPtr<JSAtom>         lazySource;
    RegExpFlag              lazyFlags;
    size_t                  lazyIndex;

    /* The latest RegExp input, set before execution. */
    HeapPtr<JSString>       pendingInput;
    RegExpFlag              flags;

    /*
     * If true, |matchesInput| and the |lazy*| fields may be used
     * to replay the last executed RegExp, and |matches| is invalid.
     */
    bool                    pendingLazyEvaluation;

    /* Linkage for preserving RegExpStatics during nested RegExp execution. */
    RegExpStatics           *bufferLink;
    bool                    copied;

  public:
    RegExpStatics() : bufferLink(NULL), copied(false) { clear(); }
    static JSObject *create(JSContext *cx, GlobalObject *parent);

  private:
    bool executeLazy(JSContext *cx);

    inline void aboutToWrite();
    inline void copyTo(RegExpStatics &dst);

    inline void restore();
    bool save(JSContext *cx, RegExpStatics *buffer) {
        JS_ASSERT(!buffer->copied && !buffer->bufferLink);
        buffer->bufferLink = bufferLink;
        bufferLink = buffer;
        if (!buffer->matches.allocOrExpandArray(matches.length())) {
            js_ReportOutOfMemory(cx);
            return false;
        }
        return true;
    }

    inline void checkInvariants();

    /*
     * Check whether the index at |checkValidIndex| is valid (>= 0).
     * If so, construct a string for it and place it in |*out|.
     * If not, place undefined in |*out|.
     */
    bool makeMatch(JSContext *cx, size_t checkValidIndex, size_t pairNum, MutableHandleValue out);
    bool createDependent(JSContext *cx, size_t start, size_t end, MutableHandleValue out);

    void markFlagsSet(JSContext *cx);

    struct InitBuffer {};
    explicit RegExpStatics(InitBuffer) : bufferLink(NULL), copied(false) {}

    friend class PreserveRegExpStatics;
    friend class AutoRegExpStaticsBuffer;

  public:
    /* Mutators. */
    inline void updateLazily(JSContext *cx, JSLinearString *input,
                             RegExpShared *shared, size_t lastIndex);
    inline bool updateFromMatchPairs(JSContext *cx, JSLinearString *input, MatchPairs &newPairs);
    inline void setMultiline(JSContext *cx, bool enabled);

    inline void clear();

    /* Corresponds to JSAPI functionality to set the pending RegExp input. */
    inline void reset(JSContext *cx, JSString *newInput, bool newMultiline);

    inline void setPendingInput(JSString *newInput);

  public:
    /* Default match accessor. */
    const MatchPairs &getMatches() const {
        /* Safe: only used by String methods, which do not set lazy mode. */
        JS_ASSERT(!pendingLazyEvaluation);
        return matches;
    }

    JSString *getPendingInput() const { return pendingInput; }

    RegExpFlag getFlags() const { return flags; }
    bool multiline() const { return flags & MultilineFlag; }

    /* Returns whether results for a non-empty match are present. */
    bool matched() const {
        /* Safe: only used by String methods, which do not set lazy mode. */
        JS_ASSERT(!pendingLazyEvaluation);
        JS_ASSERT(matches.pairCount() > 0);
        return matches[0].limit - matches[0].start > 0;
    }

    void mark(JSTracer *trc) {
        /*
         * Changes to this function must also be reflected in
         * RegExpStatics::AutoRooter::trace().
         */
        if (matchesInput)
            MarkString(trc, &matchesInput, "res->matchesInput");
        if (lazySource)
            MarkString(trc, &lazySource, "res->lazySource");
        if (pendingInput)
            MarkString(trc, &pendingInput, "res->pendingInput");
    }

    /* Value creators. */

    bool createPendingInput(JSContext *cx, MutableHandleValue out);
    bool createLastMatch(JSContext *cx, MutableHandleValue out);
    bool createLastParen(JSContext *cx, MutableHandleValue out);
    bool createParen(JSContext *cx, size_t pairNum, MutableHandleValue out);
    bool createLeftContext(JSContext *cx, MutableHandleValue out);
    bool createRightContext(JSContext *cx, MutableHandleValue out);

    /* Infallible substring creators. */

    void getParen(size_t pairNum, JSSubString *out) const;
    void getLastMatch(JSSubString *out) const;
    void getLastParen(JSSubString *out) const;
    void getLeftContext(JSSubString *out) const;
    void getRightContext(JSSubString *out) const;
};

class AutoRegExpStaticsBuffer : private JS::CustomAutoRooter
{
  public:
    explicit AutoRegExpStaticsBuffer(JSContext *cx
                                     MOZ_GUARD_OBJECT_NOTIFIER_PARAM)
      : CustomAutoRooter(cx), statics(RegExpStatics::InitBuffer()), skip(cx, &statics)
    {
        MOZ_GUARD_OBJECT_NOTIFIER_INIT;
    }

    RegExpStatics& getStatics() { return statics; }

  private:
    virtual void trace(JSTracer *trc) {
        if (statics.matchesInput) {
            MarkStringRoot(trc, reinterpret_cast<JSString**>(&statics.matchesInput),
                                "AutoRegExpStaticsBuffer matchesInput");
        }
        if (statics.lazySource) {
            MarkStringRoot(trc, reinterpret_cast<JSString**>(&statics.lazySource),
                                "AutoRegExpStaticsBuffer lazySource");
        }
        if (statics.pendingInput) {
            MarkStringRoot(trc, reinterpret_cast<JSString**>(&statics.pendingInput),
                                "AutoRegExpStaticsBuffer pendingInput");
        }
    }

    RegExpStatics statics;
    SkipRoot skip;
    MOZ_DECL_USE_GUARD_OBJECT_NOTIFIER
};

class PreserveRegExpStatics
{
    RegExpStatics * const original;
    AutoRegExpStaticsBuffer buffer;

  public:
    explicit PreserveRegExpStatics(JSContext *cx, RegExpStatics *original)
     : original(original),
       buffer(cx)
    {}

    bool init(JSContext *cx) {
        return original->save(cx, &buffer.getStatics());
    }

    ~PreserveRegExpStatics() { original->restore(); }
};

inline js::RegExpStatics *
js::GlobalObject::getRegExpStatics() const
{
    JSObject &resObj = getSlot(REGEXP_STATICS).toObject();
    return static_cast<RegExpStatics *>(resObj.getPrivate());
}

inline size_t
SizeOfRegExpStaticsData(const JSObject *obj, mozilla::MallocSizeOf mallocSizeOf)
{
    return mallocSizeOf(obj->getPrivate());
}

inline bool
RegExpStatics::createDependent(JSContext *cx, size_t start, size_t end, MutableHandleValue out)
{
    /* Private function: caller must perform lazy evaluation. */
    JS_ASSERT(!pendingLazyEvaluation);

    JS_ASSERT(start <= end);
    JS_ASSERT(end <= matchesInput->length());
    JSString *str = js_NewDependentString(cx, matchesInput, start, end - start);
    if (!str)
        return false;
    out.setString(str);
    return true;
}

inline bool
RegExpStatics::createPendingInput(JSContext *cx, MutableHandleValue out)
{
    /* Lazy evaluation need not be resolved to return the input. */
    out.setString(pendingInput ? pendingInput.get() : cx->runtime()->emptyString);
    return true;
}

inline bool
RegExpStatics::makeMatch(JSContext *cx, size_t checkValidIndex, size_t pairNum,
                         MutableHandleValue out)
{
    /* Private function: caller must perform lazy evaluation. */
    JS_ASSERT(!pendingLazyEvaluation);

    bool checkWhich  = checkValidIndex % 2;
    size_t checkPair = checkValidIndex / 2;

    if (matches.empty() || checkPair >= matches.pairCount() ||
        (checkWhich ? matches[checkPair].limit : matches[checkPair].start) < 0)
    {
        out.setUndefined();
        return true;
    }
    const MatchPair &pair = matches[pairNum];
    return createDependent(cx, pair.start, pair.limit, out);
}

inline bool
RegExpStatics::createLastMatch(JSContext *cx, MutableHandleValue out)
{
    if (!executeLazy(cx))
        return false;
    return makeMatch(cx, 0, 0, out);
}

inline bool
RegExpStatics::createLastParen(JSContext *cx, MutableHandleValue out)
{
    if (!executeLazy(cx))
        return false;

    if (matches.empty() || matches.pairCount() == 1) {
        out.setString(cx->runtime()->emptyString);
        return true;
    }
    const MatchPair &pair = matches[matches.pairCount() - 1];
    if (pair.start == -1) {
        out.setString(cx->runtime()->emptyString);
        return true;
    }
    JS_ASSERT(pair.start >= 0 && pair.limit >= 0);
    JS_ASSERT(pair.limit >= pair.start);
    return createDependent(cx, pair.start, pair.limit, out);
}

inline bool
RegExpStatics::createParen(JSContext *cx, size_t pairNum, MutableHandleValue out)
{
    JS_ASSERT(pairNum >= 1);
    if (!executeLazy(cx))
        return false;

    if (matches.empty() || pairNum >= matches.pairCount()) {
        out.setString(cx->runtime()->emptyString);
        return true;
    }
    return makeMatch(cx, pairNum * 2, pairNum, out);
}

inline bool
RegExpStatics::createLeftContext(JSContext *cx, MutableHandleValue out)
{
    if (!executeLazy(cx))
        return false;

    if (matches.empty()) {
        out.setString(cx->runtime()->emptyString);
        return true;
    }
    if (matches[0].start < 0) {
        out.setUndefined();
        return true;
    }
    return createDependent(cx, 0, matches[0].start, out);
}

inline bool
RegExpStatics::createRightContext(JSContext *cx, MutableHandleValue out)
{
    if (!executeLazy(cx))
        return false;

    if (matches.empty()) {
        out.setString(cx->runtime()->emptyString);
        return true;
    }
    if (matches[0].limit < 0) {
        out.setUndefined();
        return true;
    }
    return createDependent(cx, matches[0].limit, matchesInput->length(), out);
}

inline void
RegExpStatics::getParen(size_t pairNum, JSSubString *out) const
{
    JS_ASSERT(!pendingLazyEvaluation);

    JS_ASSERT(pairNum >= 1 && pairNum < matches.pairCount());
    const MatchPair &pair = matches[pairNum];
    if (pair.isUndefined()) {
        *out = js_EmptySubString;
        return;
    }
    out->chars  = matchesInput->chars() + pair.start;
    out->length = pair.length();
}

inline void
RegExpStatics::getLastMatch(JSSubString *out) const
{
    JS_ASSERT(!pendingLazyEvaluation);

    if (matches.empty()) {
        *out = js_EmptySubString;
        return;
    }
    JS_ASSERT(matchesInput);
    out->chars = matchesInput->chars() + matches[0].start;
    JS_ASSERT(matches[0].limit >= matches[0].start);
    out->length = matches[0].length();
}

inline void
RegExpStatics::getLastParen(JSSubString *out) const
{
    JS_ASSERT(!pendingLazyEvaluation);

    /* Note: the first pair is the whole match. */
    if (matches.empty() || matches.pairCount() == 1) {
        *out = js_EmptySubString;
        return;
    }
    getParen(matches.parenCount(), out);
}

inline void
RegExpStatics::getLeftContext(JSSubString *out) const
{
    JS_ASSERT(!pendingLazyEvaluation);

    if (matches.empty()) {
        *out = js_EmptySubString;
        return;
    }
    out->chars = matchesInput->chars();
    out->length = matches[0].start;
}

inline void
RegExpStatics::getRightContext(JSSubString *out) const
{
    JS_ASSERT(!pendingLazyEvaluation);

    if (matches.empty()) {
        *out = js_EmptySubString;
        return;
    }
    out->chars = matchesInput->chars() + matches[0].limit;
    JS_ASSERT(matches[0].limit <= int(matchesInput->length()));
    out->length = matchesInput->length() - matches[0].limit;
}

inline void
RegExpStatics::copyTo(RegExpStatics &dst)
{
    /* Destination buffer has already been reserved by save(). */
    if (!pendingLazyEvaluation)
        dst.matches.initArrayFrom(matches);

    dst.matchesInput = matchesInput;
    dst.lazySource = lazySource;
    dst.lazyFlags = lazyFlags;
    dst.lazyIndex = lazyIndex;
    dst.pendingInput = pendingInput;
    dst.flags = flags;
    dst.pendingLazyEvaluation = pendingLazyEvaluation;

    JS_ASSERT_IF(pendingLazyEvaluation, lazySource);
    JS_ASSERT_IF(pendingLazyEvaluation, matchesInput);
}

inline void
RegExpStatics::aboutToWrite()
{
    if (bufferLink && !bufferLink->copied) {
        copyTo(*bufferLink);
        bufferLink->copied = true;
    }
}

inline void
RegExpStatics::restore()
{
    if (bufferLink->copied)
        bufferLink->copyTo(*this);
    bufferLink = bufferLink->bufferLink;
}

inline void
RegExpStatics::updateLazily(JSContext *cx, JSLinearString *input,
                            RegExpShared *shared, size_t lastIndex)
{
    JS_ASSERT(input && shared);
    aboutToWrite();

    BarrieredSetPair<JSString, JSLinearString>(cx->zone(),
                                               pendingInput, input,
                                               matchesInput, input);

    lazySource = shared->source;
    lazyFlags = shared->flags;
    lazyIndex = lastIndex;
    pendingLazyEvaluation = true;
}

inline bool
RegExpStatics::updateFromMatchPairs(JSContext *cx, JSLinearString *input, MatchPairs &newPairs)
{
    JS_ASSERT(input);
    aboutToWrite();

    /* Unset all lazy state. */
    pendingLazyEvaluation = false;
    this->lazySource = NULL;
    this->lazyIndex = size_t(-1);

    BarrieredSetPair<JSString, JSLinearString>(cx->zone(),
                                               pendingInput, input,
                                               matchesInput, input);

    if (!matches.initArrayFrom(newPairs)) {
        js_ReportOutOfMemory(cx);
        return false;
    }

    return true;
}

inline void
RegExpStatics::clear()
{
    aboutToWrite();

    matches.forgetArray();
    matchesInput = NULL;
    lazySource = NULL;
    lazyFlags = RegExpFlag(0);
    lazyIndex = size_t(-1);
    pendingInput = NULL;
    flags = RegExpFlag(0);
    pendingLazyEvaluation = false;
}

inline void
RegExpStatics::setPendingInput(JSString *newInput)
{
    aboutToWrite();
    pendingInput = newInput;
}

inline void
RegExpStatics::setMultiline(JSContext *cx, bool enabled)
{
    aboutToWrite();
    if (enabled) {
        flags = RegExpFlag(flags | MultilineFlag);
        markFlagsSet(cx);
    } else {
        flags = RegExpFlag(flags & ~MultilineFlag);
    }
}

inline void
RegExpStatics::markFlagsSet(JSContext *cx)
{
    /*
     * Flags set on the RegExp function get propagated to constructed RegExp
     * objects, which interferes with optimizations that inline RegExp cloning
     * or avoid cloning entirely. Scripts making this assumption listen to
     * type changes on RegExp.prototype, so mark a state change to trigger
     * recompilation of all such code (when recompiling, a stub call will
     * always be performed).
     */
    JS_ASSERT(this == cx->global()->getRegExpStatics());

    types::MarkTypeObjectFlags(cx, cx->global(), types::OBJECT_FLAG_REGEXP_FLAGS_SET);
}

inline void
RegExpStatics::reset(JSContext *cx, JSString *newInput, bool newMultiline)
{
    aboutToWrite();
    clear();
    pendingInput = newInput;
    setMultiline(cx, newMultiline);
    checkInvariants();
}

inline void
RegExpStatics::checkInvariants()
{
#ifdef DEBUG
    if (pendingLazyEvaluation) {
        JS_ASSERT(lazySource);
        JS_ASSERT(matchesInput);
        JS_ASSERT(lazyIndex != size_t(-1));
        return;
    }

    if (matches.empty()) {
        JS_ASSERT(!matchesInput);
        return;
    }

    /* Pair count is non-zero, so there must be match pairs input. */
    JS_ASSERT(matchesInput);
    size_t mpiLen = matchesInput->length();

    /* Both members of the first pair must be non-negative. */
    JS_ASSERT(!matches[0].isUndefined());
    JS_ASSERT(matches[0].limit >= 0);

    /* Present pairs must be valid. */
    for (size_t i = 0; i < matches.pairCount(); i++) {
        if (matches[i].isUndefined())
            continue;
        const MatchPair &pair = matches[i];
        JS_ASSERT(mpiLen >= size_t(pair.limit) && pair.limit >= pair.start && pair.start >= 0);
    }
#endif /* DEBUG */
}

} /* namespace js */

inline js::RegExpStatics *
JSContext::regExpStatics()
{
    return global()->getRegExpStatics();
}

#endif /* vm_RegExpStatics_inl_h */
