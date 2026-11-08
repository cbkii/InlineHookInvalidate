# Invalidate Inline Hooks

## Fork build v1.1-alpha1

The module asks the Zygisk provider to unload its library for processes it
skips, including system_server, child zygotes, denylisted processes and
non-matching process names. Configuration is root-owned and saved atomically.
Settings apply when a process starts.

| Mode | Behaviour |
| --- | --- |
| One-shot mmap | Runs once after app specialisation, then requests module unload. Fresh installs default to this mode with remapping disabled. |
| Continuous mmap | Keeps the legacy worker and checks the remapped code every 100 ms. An existing config with no method field retains this mode. |
| Legacy pread | Keeps the legacy write-and-restore mode for existing configurations. |

An update preserves the configured targets and mode. For an existing install,
select **One-shot mmap** in the WebUI and restart the target to try it. A process
suffix such as `:remote` must be listed explicitly. One-shot cannot restore
patches applied after its callback, and the provider must honour the unload
request. Remapping executable ART pages remains experimental. Record the same
process before and after switching modes, check its functionality, and compare
its executable mappings and `InlineHookInvalidate` log entries. A mapping can
also belong to the provider or another module.

Hello, it's **ObbedCode** here with some cool stuff.

I was bored, so I quickly whipped up a couple of projects in my spare time on my relax day. Took about 10 minutes, nothing crazy. This is the same thing LSPosed has in their system under **Settings -> "Invalidate inline Hooks"**.
To be Clear this is not SPOOFING, this is more so Invalidating Inline Hooks!

## What This Does

LSPosed-like frameworks (including Frida) make modifications to `libart.so` to do their bidding. Those modifications applied to `libart.so` are obviously detectable via a CRC hash, i.e. hash the `libart.so` loaded in memory and compare it against the one on disk.

All this module does is basically reload `libart.so` back into memory from disk, hence the LSPosed name **"Invalidate inline Hooks"**.

In short: this module makes the integrity checks on the library loaded in memory match the hash of the one found on disk, so the in-memory library looks clean and safe. It will invalidate any hooks or patches made to the in-memory library, but ART-style hooks from a module still remain, since those are applied a bit differently and don't rely 100% on patching `libart.so`.

That's all this module does. If something is still being detected or not working, that is out of scope.

> **Note:** Sometimes it does not spoof in time. Keep that in mind - it is possible a timed integrity check may catch it.

## Does This Break Your Module's Hooks?

You may wonder if this affects the ART method hooks deployed from LSPosed-like frameworks, making it a feature that isn't useful because it destroys your hooks.

The answer is **no**. ART method hooks are still applied - they are applied in a certain way. Either way, **only** the hooks/patches on `libart.so` are invalidated or removed.

Here is a list of symbols that LSPosed will hook:

```
art::ClassLinker::FixupStaticTrampolines
art::ClassLinker::RegisterNative
art::ClassLinker::UnregisterNative
art::ClassLinker::VisiblyInitializedCallback::AdjustThreadVisibilityCounter
art::instrumentation::Instrumentation::InstallStubsForClass
art::jit::Jit::MapBootImageMethods
art::jit::Jit::AddCompileTask
art::jit::Jit::EnqueueOptimizedCompilation
art::jit::JitCodeCache::GarbageCollectCache
art::mirror::Class::SetStatus
art::FetchStackTraceVisitor::VisitFrame
art::BuildInternalStackTraceVisitor::VisitFrame
```

Once LSPosed applies the ART method hooks (i.e. applies your hooks from your module), then in theory the modifications to `libart.so` are no longer needed.

As LSPosed itself warns about this feature:

> Cleanup libart.so for listed apps. This will cause random malfunctions and crashes. Use only when unable to open specific apps.

From my use case, it causes no issues.

## Scope

This module has **one purpose**, and it does that one job - that is all. Any other issues or detections are unrelated. So please don't waste your time telling me to check out some app or that some app is detecting something.

---

# Detecting ART Hooks

It is possible to detect ART hooks, despite some people claiming you can't. Here are the ways to still detect them.

Now, as a wise man once said: "If you wanna prove you can detect, just prove it by action, not words" - and that I have. I will not release any detectors, but assuming you do have a brain, you can understand the upcoming concepts and how they work. From there, you can implement your own detector tool - unless you find the task too complex.

## 1. Stack Trace

When you dump the stack trace within the context of a suspected hooked Java method, and it is hooked, you will see traces on the stack trace.

In the context of LSPosed: let's say the app targeted for hooking is `com.cool.test.app`, the class of the target method is `CoolClass`, and the method being hooked is `pleaseDoNotHookMe()`.

When `pleaseDoNotHookMe()` is hooked and the stack trace is dumped, it will look something like this:

```
[1] com.cool.test.app.CoolClass.pleaseDoNotHookMe(CoolClass.java)
[2] java.lang.reflect.Method.invoke(Native Method)
[3] AEEQqd0Fdx.PvM.piUxF.c.uITvIHy.xCH.HookBridge.invokeOriginalMethod(Native Method)
[4] h.proceed(...)
[5] o1.proceed(...)
[6] p1.intercept(...)
[7] h0.callback(...)
[8] android.telephony.DrouleangVeen.pleaseDoNotHookMe(DrouleangVeen.java)
```

Using the modern framework, elements 4-7 may differ, but it looks somewhat like the above.

- **Element 8** - LSPosed selects a random package name from a list of real package names (here, `android.telephony.`), then generates a random class name (here, `DrouleangVeen`). That becomes the class where the hooked method is inserted, like a stub.
- **Elements 7-4** - the `proceed` / `intercept` / `callback` methods from LSPosed.
- **Element 3** - the `HookBridge` from LSPosed calling back to the original method. To make that call back, it uses reflection to bridge it, hence `Method.invoke` at element 2.

If `pleaseDoNotHookMe()` were **not** hooked, elements 2-8 would not appear on the stack trace.

There are a few APIs you can use to dump a stack trace, and they matter here because LSPosed treats each of them differently:

- `Thread.getStackTrace()` (or `Thread.currentThread().getStackTrace()`) - the standard, most common way, and the one LSPosed sanitizes.
- `java.lang.Throwable.nativeFillInStackTrace` - the JNI method that actually builds the stack trace under the hood (what `new Throwable().getStackTrace()` relies on). This is the one LSPosed mainly hooks to modify the results.
- `dalvik.system.VMStack.getAnnotatedThreadStackTrace(Thread.currentThread())` - an alternate, lesser-used API (behind the hidden-API restriction). They don't hook this one yet, so it bypasses the sanitization.

### LSPosed's Mitigations

LSPosed does have mitigations for this kind of detection. As listed above, `libart.so` is patched on some stack-trace symbols. If we invalidate `libart.so`, we can assume it will no longer intercept stack traces to clean them and hide its traces.

But LSPosed actually relies more on hooking the ART method `java.lang.Throwable.nativeFillInStackTrace`. That method is a JNI method that creates a stack trace; hooking it lets them modify the stack-trace results.

Note the following:

- If you dump the stack trace **directly from** the method you suspect of being hooked (and it is hooked), LSPosed will fail to clean those results.
- But if you dump the stack trace from any **other** method called **after** the hooked method, the results will be sanitized to remove the LSPosed traces.
- Using the alternate Java API `dalvik.system.VMStack.getAnnotatedThreadStackTrace(Thread.currentThread())` (bypassing the hidden-API restriction) will bypass any of the sanitization. They don't hook that API (yet). It has been reported to the LSPosed dev, and they will eventually support it.

### If Both APIs Get Sanitized

Even if they were to 100% sanitize both APIs fully, you can **still** detect the ART method hook traces via the stack trace - but this requires you to **manually implement the stack-trace visiting system**.

The idea is to walk the managed call stack yourself, frame by frame, the same way ART does internally, instead of asking ART for a finished, "helpful" (sanitized) list. If you build the walk yourself, the framework never gets the chance to filter its own frames out of the result. In our example, walking the stack from inside `pleaseDoNotHookMe()` would still expose the `HookBridge.invokeOriginalMethod` / `proceed` / `intercept` / `callback` frames (elements 2-7), because you saw them directly rather than through an API they can intercept.

Android is open source, so in theory you may think this is easy. From experience, this was by far one of the most difficult things to implement without requiring `libart.so`. Resolving each managed frame means dealing with every bridge/entry type ART can put on the stack (interpreter, quick-compiled, JNI, and the various trampolines), and the layout of those changes across Android versions.

My implementation (closed source) is fully `libart.so`-independent, successfully resolves all managed ART frames / bridge types, and supports Android 7+. As I said, it was not easy and took nearly six attempts, but it is very useful: it can't be manipulated by a hook, and any `libart.so` modifications don't matter, since it is `libart.so`-independent.

## 2. JNI / Entry-Point Verification

Every Java and native method has a backing `ArtMethod` structure in memory. This method inspects that structure directly, so it doesn't care what the stack trace says or whether `libart.so` looks clean - a hook has to redirect *where the method runs*, and that redirection lives in these fields.

First, get the `ArtMethod` pointer for the method you want to check (for example `CoolClass.pleaseDoNotHookMe`). The usual trick is to reflect the `Method` and read the hidden `artMethod` field off it, or resolve it through JNI. Then read the fields:

**Step 1 - read `access_flags` and check the `kAccNative` bit.** This tells you whether the method is native, which decides which pointer actually matters.

**Step 2a - native method: check the JNI pointer at `+0x10`.** This is the native function the method dispatches to. For a legit native method it points **inside a file-backed `.so`** (something with a real path on disk, like `libart.so` or the app's own library). It is hooked if that pointer:

- lands **outside** any file-backed `.so` (an anonymous / foreign mapping - a native pointer replacement, Frida-style), or
- lands **inside the LSPosed trampoline memfd** (an anonymous, in-memory `memfd:` region, not a real file).

**Step 2b - non-native method: classify the quick entry at `+0x18`.** This is the "quick" entry point, i.e. where execution actually goes when the method is called. It is legit if it points to one of:

- the **libart bridge** (the interpreter / quick-to-interpreter bridge),
- the app's own compiled **`.oat`**, or
- the **normal JIT code cache**.

It is hooked if the quick entry is instead redirected **into the LSPlant trampoline**, or into **anonymous / foreign memory** that doesn't belong to any of the above.

**Step 3 - corroborate with the twin at `+0x20`.** When LSPlant hooks a method it keeps a backup ("twin") `ArtMethod` for the original. If that twin also points into the trampoline, it's strong corroboration that the method above it is really hooked rather than just looking odd.

> **Note:** These offsets (`+0x10`, `+0x18`, `+0x20`, `access_flags`) vary by device and Android version. My system handles and resolves all offsets properly, so it would be up to you to resolve them for your target.

## 3. JIT Recompilation (Behavioral)

The two methods above read a single snapshot. This one is **behavioral**, and it catches a hook style the snapshot approach is blind to: a hook applied via **ART deoptimization**, which doesn't redirect any entry-point pointer at all - it just forces the method to keep running in the interpreter (via the `kAccCompileDontBother` flag). Because nothing is redirected, `access_flags` / `+0x18` can look perfectly clean; the tell is in the *behavior* over time.

**Requires:** a real `JNIEnv`, so it runs in `JNI_OnLoad` (not the static constructor). You need your suspect method (`pleaseDoNotHookMe`) and an **unhooked control method on the same class** - call it `controlProbe`. Same class matters, because both methods then face the same JIT pressure and the control tells you whether the JIT was even active this run.

**How it works:**

1. Grab the quick entry point (`+0x18`) of both methods as a baseline.
2. Call both methods an equal number of times (~3000x works), sampling each one's quick entry every ~100 calls.
3. Watch whether each entry point **moves**. A normal method starts cold (interpreter / bridge address) and, once it gets hot enough, ART recompiles it and the quick entry **migrates** to a freshly JIT-compiled address. A method pinned to the interpreter by a deopt-style hook **never migrates**, no matter how many times you call it - and that "never moves under load" is the anomaly.

**Verdict:**

| Control method | Suspect method | Result |
|----------------|----------------|--------|
| Never moved | - | **INCONCLUSIVE** - JIT pressure wasn't exercised this run, so the test proves nothing |
| Moved | Didn't move | **SUSPECT** - the suspect refused to JIT-compile where the control did |
| Moved | Moved | **PASS** - behaved like a normal method |

## 4. Dirty Pages (`/proc/self/smaps`)

Another easy way to detect such abnormalities is to use `/proc/self/smaps` to find a dirty mapping.

I came across a module that possibly did something similar to the one I made here - I don't remember how it landed on my desk. One thing is for sure: there were claims about how it can't be detected, something along the lines of a vibe coder.

His approach was to use a combination of `mprotect` + `popen`. That approach won't fix the `Private_Dirty` issue it leaves behind. Therefore, simply checking the `.so` in smaps for `Private_Dirty` is enough to detect that approach.

Now, to be fair, his module barely worked - the UI wasn't all there and couldn't be opened from actions. It did have a WebUI, just not a UI that could be opened from actions. Even when you manage to use the UI, I still don't think it would have passed a CRC check to begin with when applied on a target app.

---

There may be a couple of other ways, but this is proof in general that such things can still be easily detected.

Sure, an integrity check on the in-memory library against the one on disk will always pass, but that doesn't mean ART method hooks can't still be detected. There are more ways. Don't listen to anyone who says otherwise - they may be a vibe coder, or someone who loves Kids, I'm not sure.

Enjoy your day! Much love, ObbedCode <3
