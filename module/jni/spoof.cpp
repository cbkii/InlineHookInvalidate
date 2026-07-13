
// Method 1 : JNI-table pointer hook on gJniNativeInterface (libart .data.rel.ro / RELRO). Redirects a
//            JNI function process-wide by writing a pointer into libart's own data segment. Bypass
//            r-x-only coe integrity (SEGCRC) because .text is never touched; leaves a Private_Dirty
//            page in libart's RELRO. Verified live: DIRTYMAP RELRO priv_dirty 0 -> 4kB, slot -> module.
// Method 2 : libart GOT / .data.rel.ro JUMP_SLOT redirect. Sme "pointer into system-lib data" family.
// Method 3 : deoptimization hook. Points a target method's ArtMethod quickk entry-point at a legitimate
//            libart address (art_quick_to_interpreter_bridge) and sets kAccCompileDontBother, pinning
//              it to the interpreter. Bypasses entry-point provenance (EPP) and SEGCRC and dirties no
//            libart page; only a behavioral JIT-recompilation-durability probe catches it. Verified.
//  We are to try other ways, but that will be for another itme

#include <android/log.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

#include <jni.h>

#include "xdl/xdl.h"

namespace spoof {

constexpr char kLogTag[] = "InlineHookInvalidate";

void *pointerHookSlotAddress = nullptr;
void *pointerHookValue = nullptr;

void reapplyPointerHook(std::int64_t pageSize) {
    std::uintptr_t slotAddress = reinterpret_cast<std::uintptr_t>(pointerHookSlotAddress);
    std::uintptr_t pageAlignedAddress = slotAddress & ~(pageSize - 1);
    std::size_t mappedLength =
        ((slotAddress + sizeof(void *) + pageSize - 1) & ~(pageSize - 1)) - pageAlignedAddress;
    if (mprotect(reinterpret_cast<void *>(pageAlignedAddress), mappedLength, PROT_READ | PROT_WRITE) != 0)
        return;

    *reinterpret_cast<void **>(slotAddress) = pointerHookValue;
    mprotect(reinterpret_cast<void *>(pageAlignedAddress), mappedLength, PROT_READ);
}

void runPointerHookLoop() {
    if (pointerHookSlotAddress == nullptr || pointerHookValue == nullptr)
        return;

    const std::int64_t pageSize = sysconf(_SC_PAGESIZE);
    reapplyPointerHook(pageSize);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "pointer hook active on slot %p, monitoring continuously", pointerHookSlotAddress);
    constexpr std::chrono::milliseconds kPollInterval{100};
    while (true) {
        std::this_thread::sleep_for(kPollInterval);
        if (*reinterpret_cast<void **>(pointerHookSlotAddress) != pointerHookValue) {
            reapplyPointerHook(pageSize);
        }
    }
}

const char *(*originalGetStringUtfChars)(JNIEnv *, jstring, jboolean *) = nullptr;

const char *hookedGetStringUtfChars(JNIEnv *environment, jstring javaString, jboolean *isCopy) {
    return originalGetStringUtfChars(environment, javaString, isCopy);
}

bool installJniTablePointerHook(JNIEnv *environment) {
    if (environment == nullptr || environment->functions == nullptr)
        return false;

    JNINativeInterface *jniTable = const_cast<JNINativeInterface *>(environment->functions);
    originalGetStringUtfChars = jniTable->GetStringUTFChars;
    pointerHookSlotAddress = reinterpret_cast<void *>(&jniTable->GetStringUTFChars);
    pointerHookValue = reinterpret_cast<void *>(hookedGetStringUtfChars);
    return true;
}

int (*originalMprotect)(void *, size_t, int) = nullptr;

int hookedMprotect(void *targetAddress, size_t length, int protection) {
    return originalMprotect(targetAddress, length, protection);
}

bool installLibartGotPointerHook(const std::string &libraryName, const char *importedSymbolName) {
    void *libraryHandle = xdl_open(libraryName.c_str(), XDL_DEFAULT);
    if (libraryHandle == nullptr)
        return false;

    xdl_info_t libraryInfo{};
    if (xdl_info(libraryHandle, XDL_DI_DLINFO, &libraryInfo) != 0 || libraryInfo.dlpi_phdr == nullptr) {
        xdl_close(libraryHandle);
        return false;
    }

    std::uintptr_t loadBias = reinterpret_cast<std::uintptr_t>(libraryInfo.dli_fbase);
    const ElfW(Dyn) *dynamicSection = nullptr;
    for (std::size_t index = 0; index < libraryInfo.dlpi_phnum; index++) {
        if (libraryInfo.dlpi_phdr[index].p_type == PT_DYNAMIC) {
            dynamicSection = reinterpret_cast<const ElfW(Dyn) *>(loadBias + libraryInfo.dlpi_phdr[index].p_vaddr);
            break;
        }
    }
    if (dynamicSection == nullptr) {
        xdl_close(libraryHandle);
        return false;
    }

    const char *stringTable = nullptr;
    const ElfW(Sym) *symbolTable = nullptr;
    const ElfW(Rela) *pltRelocations = nullptr;
    std::size_t pltRelocationBytes = 0;
    for (const ElfW(Dyn) *entry = dynamicSection; entry->d_tag != DT_NULL; entry++) {
        if (entry->d_tag == DT_STRTAB) {
            stringTable = reinterpret_cast<const char *>(loadBias + entry->d_un.d_ptr);
        } else if (entry->d_tag == DT_SYMTAB) {
            symbolTable = reinterpret_cast<const ElfW(Sym) *>(loadBias + entry->d_un.d_ptr);
        } else if (entry->d_tag == DT_JMPREL) {
            pltRelocations = reinterpret_cast<const ElfW(Rela) *>(loadBias + entry->d_un.d_ptr);
        } else if (entry->d_tag == DT_PLTRELSZ) {
            pltRelocationBytes = entry->d_un.d_val;
        }
    }
    if (stringTable == nullptr || symbolTable == nullptr || pltRelocations == nullptr || pltRelocationBytes == 0) {
        xdl_close(libraryHandle);
        return false;
    }

    std::size_t relocationCount = pltRelocationBytes / sizeof(ElfW(Rela));
    for (std::size_t index = 0; index < relocationCount; index++) {
        const ElfW(Rela) &relocation = pltRelocations[index];
        std::size_t symbolIndex = ELF64_R_SYM(relocation.r_info);
        const char *symbolName = stringTable + symbolTable[symbolIndex].st_name;
        if (strcmp(symbolName, importedSymbolName) != 0)
            continue;

        std::uintptr_t slotAddress = loadBias + relocation.r_offset;
        originalMprotect = reinterpret_cast<int (*)(void *, size_t, int)>(*reinterpret_cast<void **>(slotAddress));
        pointerHookSlotAddress = reinterpret_cast<void *>(slotAddress);
        pointerHookValue = reinterpret_cast<void *>(hookedMprotect);
        xdl_close(libraryHandle);

        __android_log_print(ANDROID_LOG_INFO, kLogTag,
                            "resolved GOT pointer hook on %s in %s slot %p (original %p)",
                            importedSymbolName, libraryName.c_str(),
                            reinterpret_cast<void *>(slotAddress), reinterpret_cast<void *>(originalMprotect));
        return true;
    }

    xdl_close(libraryHandle);
    return false;
}

JavaVM *deoptJavaVm = nullptr;
std::uintptr_t deoptArtMethod = 0;
void *deoptInterpreterBridge = nullptr;

constexpr std::uint32_t kAccCompileDontBother = 0x02000000;
constexpr std::size_t kArtMethodAccessFlagsOffset = 0x04;
constexpr std::size_t kArtMethodQuickEntryOffset = 0x18;

void *resolveLibrarySymbol(const std::string &libraryName, const char *symbolName) {
    void *libraryHandle = xdl_open(libraryName.c_str(), XDL_DEFAULT);
    if (libraryHandle == nullptr)
        return nullptr;

    std::size_t symbolSize = 0;
    void *symbolAddress = xdl_dsym(libraryHandle, symbolName, &symbolSize);
    if (symbolAddress == nullptr) {
        symbolAddress = xdl_sym(libraryHandle, symbolName, &symbolSize);
    }
    xdl_close(libraryHandle);
    return symbolAddress;
}

std::uintptr_t resolveApplicationStaticArtMethod(JNIEnv *environment, const char *className,
                                                 const char *methodName, const char *methodSignature) {
    jclass activityThreadClass = environment->FindClass("android/app/ActivityThread");
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (activityThreadClass == nullptr)
        return 0;

    jmethodID currentApplicationMethod = environment->GetStaticMethodID(activityThreadClass, "currentApplication", "()Landroid/app/Application;");
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (currentApplicationMethod == nullptr)
        return 0;

    jobject application = environment->CallStaticObjectMethod(activityThreadClass, currentApplicationMethod);
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (application == nullptr)
        return 0;

    jclass contextClass = environment->FindClass("android/content/Context");
    jmethodID getClassLoaderMethod = contextClass == nullptr ? nullptr : environment->GetMethodID(contextClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (getClassLoaderMethod == nullptr)
        return 0;

    jobject classLoader = environment->CallObjectMethod(application, getClassLoaderMethod);
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (classLoader == nullptr)
        return 0;

    jclass classLoaderClass = environment->FindClass("java/lang/ClassLoader");
    jmethodID loadClassMethod = classLoaderClass == nullptr ? nullptr : environment->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (loadClassMethod == nullptr)
        return 0;

    jstring classNameString = environment->NewStringUTF(className);
    jobject loadedClassObject = environment->CallObjectMethod(classLoader, loadClassMethod, classNameString);
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (loadedClassObject == nullptr)
        return 0;

    jclass targetClass = static_cast<jclass>(loadedClassObject);
    jmethodID targetMethod = environment->GetStaticMethodID(targetClass, methodName, methodSignature);
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (targetMethod == nullptr)
        return 0;

    jobject reflectedMethod = environment->ToReflectedMethod(targetClass, targetMethod, JNI_TRUE);
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    jclass executableClass = environment->FindClass("java/lang/reflect/Executable");
    jfieldID artMethodField = executableClass == nullptr ? nullptr : environment->GetFieldID(executableClass, "artMethod", "J");
    if (environment->ExceptionCheck()) environment->ExceptionClear();
    if (reflectedMethod == nullptr || artMethodField == nullptr)
        return 0;

    return static_cast<std::uintptr_t>(environment->GetLongField(reflectedMethod, artMethodField));
}

void applyDeoptimization() {
    if (deoptArtMethod == 0)
        return;

    const std::int64_t pageSize = sysconf(_SC_PAGESIZE);
    std::uintptr_t pageAlignedAddress = deoptArtMethod & ~(pageSize - 1);
    std::size_t mappedLength = ((deoptArtMethod + kArtMethodQuickEntryOffset + sizeof(void *) + pageSize - 1) & ~(pageSize - 1)) - pageAlignedAddress;
    mprotect(reinterpret_cast<void *>(pageAlignedAddress), mappedLength, PROT_READ | PROT_WRITE);
    std::uint32_t *accessFlags = reinterpret_cast<std::uint32_t *>(deoptArtMethod + kArtMethodAccessFlagsOffset);
    *accessFlags |= kAccCompileDontBother;
    if (deoptInterpreterBridge != nullptr) {
        *reinterpret_cast<void **>(deoptArtMethod + kArtMethodQuickEntryOffset) = deoptInterpreterBridge;
    }
}

void runDeoptimizationLoop(std::string libraryName, std::string className,
                           std::string methodName, std::string methodSignature) {
    if (deoptJavaVm == nullptr)
        return;

    JNIEnv *environment = nullptr;
    if (deoptJavaVm->AttachCurrentThread(&environment, nullptr) != JNI_OK)
        return;

    deoptInterpreterBridge = resolveLibrarySymbol(libraryName, "art_quick_to_interpreter_bridge");

    for (std::int32_t attempt = 0; attempt < 1200 && deoptArtMethod == 0; attempt++) {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        if (environment->PushLocalFrame(32) != 0)
            continue;

        deoptArtMethod = resolveApplicationStaticArtMethod(environment, className.c_str(), methodName.c_str(), methodSignature.c_str());
        environment->PopLocalFrame(nullptr);
    }

    if (deoptArtMethod == 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "deopt could not resolve %s.%s", className.c_str(), methodName.c_str());
        deoptJavaVm->DetachCurrentThread();
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "deopt pinning %s.%s am=0x%lx to interpreter bridge %p, monitoring continuously",
                        className.c_str(), methodName.c_str(),
                        static_cast<unsigned long>(deoptArtMethod), deoptInterpreterBridge);

    constexpr std::chrono::milliseconds kPollInterval{100};
    while (true) {
        applyDeoptimization();
        std::this_thread::sleep_for(kPollInterval);
    }
}

}
