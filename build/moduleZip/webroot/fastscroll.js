"use strict";

// Draggable fast-scrollbar. Supports multiple scrollers: #scroller is auto-attached; other views (e.g. the
// log view) call FastScroll.attach(element). Each scroller gets its own track/thumb.
(function () {
    const MIN_THUMB = 44;
    const HIDE_DELAY = 1400;

    function createInstance(scroller) {
        const track = document.createElement("div");
        track.className = "fastscroll-track";
        const thumb = document.createElement("div");
        thumb.className = "fastscroll-thumb";
        track.appendChild(thumb);
        document.body.appendChild(track);

        let dragging = false;
        let dragOffset = 0;
        let hideTimer = 0;

        function visible() {
            // Only show this scroller's bar when its scroller is actually on screen.
            return scroller.offsetParent !== null && scroller.clientHeight > 0;
        }

        function update() {
            if (!visible()) { track.classList.remove("scrollable", "visible"); return; }
            const rect = scroller.getBoundingClientRect();
            const trackHeight = scroller.clientHeight;
            const content = scroller.scrollHeight;
            track.style.top = rect.top + "px";
            track.style.height = trackHeight + "px";
            if (content <= trackHeight + 4) { track.classList.remove("scrollable"); return; }
            track.classList.add("scrollable");
            const thumbHeight = Math.max(MIN_THUMB, trackHeight * trackHeight / content);
            const maxScroll = content - trackHeight;
            const maxThumb = trackHeight - thumbHeight;
            const top = maxScroll > 0 ? (scroller.scrollTop / maxScroll) * maxThumb : 0;
            thumb.style.height = thumbHeight + "px";
            thumb.style.transform = "translateY(" + top + "px)";
        }

        function show() {
            if (!visible()) return;
            track.classList.add("visible");
            clearTimeout(hideTimer);
            if (!dragging) hideTimer = setTimeout(() => track.classList.remove("visible"), HIDE_DELAY);
        }

        function onScroll() { update(); show(); }

        function onPointerMove(event) {
            if (!dragging) return;
            const trackTop = scroller.getBoundingClientRect().top;
            const trackHeight = scroller.clientHeight;
            const content = scroller.scrollHeight;
            const maxThumb = trackHeight - thumb.offsetHeight;
            let position = event.clientY - trackTop - dragOffset;
            position = Math.max(0, Math.min(position, maxThumb));
            const ratio = maxThumb > 0 ? position / maxThumb : 0;
            scroller.scrollTop = ratio * (content - trackHeight);
            event.preventDefault();
        }

        function onPointerUp() {
            dragging = false;
            thumb.removeEventListener("pointermove", onPointerMove);
            thumb.removeEventListener("pointerup", onPointerUp);
            thumb.removeEventListener("pointercancel", onPointerUp);
            show();
        }

        function onPointerDown(event) {
            dragging = true;
            track.classList.add("visible");
            clearTimeout(hideTimer);
            dragOffset = event.clientY - thumb.getBoundingClientRect().top;
            thumb.setPointerCapture(event.pointerId);
            thumb.addEventListener("pointermove", onPointerMove);
            thumb.addEventListener("pointerup", onPointerUp);
            thumb.addEventListener("pointercancel", onPointerUp);
            event.preventDefault();
        }

        thumb.addEventListener("pointerdown", onPointerDown);
        scroller.addEventListener("scroll", onScroll, { passive: true });
        window.addEventListener("resize", update);
        update();
        return { update: update, show: show };
    }

    const instances = [];

    function attach(scroller) {
        if (!scroller) return null;
        const inst = createInstance(scroller);
        instances.push(inst);
        return inst;
    }

    window.FastScroll = {
        attach: attach,
        update: () => instances.forEach((i) => i.update()),
        show: () => instances.forEach((i) => i.show())
    };

    function build() { attach(document.getElementById("scroller")); }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", build);
    else build();
})();
