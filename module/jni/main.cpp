#include <android/log.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "xdl/xdl.h"
#include "zygisk.hpp"

namespace {
//TODO: just use LOG Macros 
constexpr char kLogTag[] = "InlineHookInvalidate";
constexpr char kConfigPath[] = "/data/adb/modules/inline_hook_invalidate/config.txt";
constexpr char kDefaultLibraryName[] = "libart.so";

enum class RemapMethod {
    Mmap,
    MprotectPread
};

struct ModuleConfiguration {
    bool enabled = false;
    std::string libraryName = kDefaultLibraryName;
    RemapMethod method = RemapMethod::Mmap;
    std::vector<std::string> targetPackages;
};

std::string trimLineEnding(const std::string &line) {
    std::size_t end = line.size();
    while (end > 0 && (line[end - 1] == '\r' || line[end - 1] == '\n')) {
        end--;
    }
    return line.substr(0, end);
}

std::vector<std::string> splitOnColon(const std::string &value) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        std::size_t separator = value.find(':', start);
        if (separator == std::string::npos) {
            parts.push_back(value.substr(start));
            break;
        }
        parts.push_back(value.substr(start, separator - start));
        start = separator + 1;
    }
    return parts;
}

bool readModuleConfiguration(ModuleConfiguration *configuration) {
    std::ifstream configurationFile(kConfigPath);
    if (!configurationFile.is_open())
        return false;

    std::string firstLine;
    if (!std::getline(configurationFile, firstLine))
        return false;

    firstLine = trimLineEnding(firstLine);

    std::vector<std::string> headerParts = splitOnColon(firstLine);
    if (!headerParts.empty())                                   configuration->enabled = headerParts[0] == "1";
    if (headerParts.size() >= 2 && !headerParts[1].empty())     configuration->libraryName = headerParts[1];
    if (headerParts.size() >= 3 && headerParts[2] == "pread")   configuration->method = RemapMethod::MprotectPread;


    std::string packageLine;
    while (std::getline(configurationFile, packageLine)) {
        packageLine = trimLineEnding(packageLine);
        if (!packageLine.empty()) {
            configuration->targetPackages.push_back(packageLine);
        }
    }
    return true;
}

bool targetListContainsProcess(const std::vector<std::string> &targetPackages, const std::string &processName) {
    for (const std::string &packageName : targetPackages) {
        if (packageName == processName) {
            return true;
        }
    }
    return false;
}

struct ExecutableSegment {
    std::uintptr_t liveAddress = 0;
    std::uintptr_t fileOffset = 0;
    std::size_t length = 0;
    std::uint32_t expectedChecksum = 0;
};

struct LocatedLibrary {
    bool found = false;
    std::string realPath;
    std::vector<ExecutableSegment> segments;
};

std::uint32_t computeFnv1aChecksum(const void *address, std::size_t length) {
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(address);
    std::uint32_t checksum = 2166136261u;
    for (std::size_t index = 0; index < length; index++) {
        checksum ^= bytes[index];
        checksum *= 16777619u;
    }
    return checksum;
}

LocatedLibrary locateExecutableSegments(const std::string &libraryName) {
    LocatedLibrary result;

    void *libraryHandle = xdl_open(libraryName.c_str(), XDL_DEFAULT);
    if (libraryHandle == nullptr)
        return result;

    xdl_info_t libraryInfo{};
    if (xdl_info(libraryHandle, XDL_DI_DLINFO, &libraryInfo) == 0 &&
        libraryInfo.dli_fname != nullptr && libraryInfo.dlpi_phdr != nullptr) {
        result.realPath = libraryInfo.dli_fname;
        for (std::size_t segmentIndex = 0; segmentIndex < libraryInfo.dlpi_phnum; segmentIndex++) {
            const ElfW(Phdr) &programHeader = libraryInfo.dlpi_phdr[segmentIndex];
            if (programHeader.p_type != PT_LOAD || !(programHeader.p_flags & PF_X))
                continue;

            ExecutableSegment segment;
            segment.liveAddress = reinterpret_cast<std::uintptr_t>(libraryInfo.dli_fbase) + programHeader.p_vaddr;
            segment.fileOffset = programHeader.p_offset;
            segment.length = programHeader.p_filesz;
            result.segments.push_back(segment);
        }
        result.found = !result.segments.empty();
    }

    xdl_close(libraryHandle);
    return result;
}

bool remapSegmentFromDisk(int fileDescriptor, const ExecutableSegment &segment, std::int64_t pageSize, bool useMmap) {
    std::uintptr_t offsetWithinPage     = segment.liveAddress & (pageSize - 1);
    std::uintptr_t pageAlignedAddress   = segment.liveAddress - offsetWithinPage;
    std::size_t pageAlignedLength       = ((segment.liveAddress + segment.length + pageSize - 1) & ~(pageSize - 1)) - pageAlignedAddress;

    if (useMmap) {
        off_t mappingOffset = static_cast<off_t>(segment.fileOffset) - static_cast<off_t>(offsetWithinPage);
        void *mappedRegion = mmap(reinterpret_cast<void *>(pageAlignedAddress), pageAlignedLength, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fileDescriptor, mappingOffset);
        return mappedRegion != MAP_FAILED && reinterpret_cast<std::uintptr_t>(mappedRegion) == pageAlignedAddress;
    }

    if (mprotect(reinterpret_cast<void *>(pageAlignedAddress), pageAlignedLength, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;

    ssize_t bytesRead = pread(fileDescriptor, reinterpret_cast<void*>(segment.liveAddress), segment.length, segment.fileOffset);
    mprotect(reinterpret_cast<void *>(pageAlignedAddress), pageAlignedLength, PROT_READ | PROT_EXEC);
    return bytesRead == static_cast<ssize_t>(segment.length);
}

void runContinuousRemapLoop(std::string libraryName, bool useMmap) {
    LocatedLibrary library = locateExecutableSegments(libraryName);
    if (!library.found) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "could not locate executable segments of %s", libraryName.c_str());
        return;
    }

    int fileDescriptor = open(library.realPath.c_str(), O_RDONLY);
    if (fileDescriptor < 0) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "open failed for %s: %s", library.realPath.c_str(), strerror(errno));
        return;
    }

    const std::int64_t pageSize = sysconf(_SC_PAGESIZE);
    std::int32_t initialRemapCount = 0;
    for (ExecutableSegment &segment : library.segments) {
        if (remapSegmentFromDisk(fileDescriptor, segment, pageSize, useMmap)) {
            segment.expectedChecksum = computeFnv1aChecksum(reinterpret_cast<const void *>(segment.liveAddress), segment.length);
            initialRemapCount++;
        }
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag, "remapped %d executable segment(s) of %s from %s using %s, now monitoring continuously", initialRemapCount, libraryName.c_str(), library.realPath.c_str(), useMmap ? "mmap" : "mprotect+pread");
    constexpr std::chrono::milliseconds kPollInterval{100};
    while (true) {
        std::this_thread::sleep_for(kPollInterval);
        for (ExecutableSegment &segment : library.segments) {
            std::uint32_t liveChecksum = computeFnv1aChecksum(reinterpret_cast<const void *>(segment.liveAddress), segment.length);
            if (liveChecksum == segment.expectedChecksum) {
                continue;
            }
            __android_log_print(ANDROID_LOG_WARN, kLogTag, "live modification of %s detected (checksum 0x%08x != 0x%08x), remapping", libraryName.c_str(), liveChecksum, segment.expectedChecksum);
            if (remapSegmentFromDisk(fileDescriptor, segment, pageSize, useMmap)) {
                segment.expectedChecksum = computeFnv1aChecksum(reinterpret_cast<const void *>(segment.liveAddress), segment.length);
                __android_log_print(ANDROID_LOG_INFO, kLogTag, "re-remapped %s (checksum now 0x%08x)", libraryName.c_str(), segment.expectedChecksum);
            }
        }
    }
}

}

class InlineHookInvalidate : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *moduleApi, JNIEnv *moduleEnvironment) override {
        api = moduleApi;
        environment = moduleEnvironment;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *) override {
        haveConfiguration = readModuleConfiguration(&cachedConfiguration);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *arguments) override {
        if (!haveConfiguration || !cachedConfiguration.enabled)
            return;
        if (arguments->nice_name == nullptr)
            return;

        const char *processNameCharacters = environment->GetStringUTFChars(arguments->nice_name, nullptr);
        if (processNameCharacters == nullptr)
            return;

        std::string processName(processNameCharacters);
        environment->ReleaseStringUTFChars(arguments->nice_name, processNameCharacters);

        if (targetListContainsProcess(cachedConfiguration.targetPackages, processName)) {
            bool useMmap = cachedConfiguration.method == RemapMethod::Mmap;
            std::thread remapThread(runContinuousRemapLoop, cachedConfiguration.libraryName, useMmap);
            remapThread.detach();
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *environment = nullptr;
    bool haveConfiguration = false;
    ModuleConfiguration cachedConfiguration;
};

REGISTER_ZYGISK_MODULE(InlineHookInvalidate)
