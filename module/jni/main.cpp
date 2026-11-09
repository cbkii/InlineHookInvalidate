#include <android/log.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <link.h>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "xdl/xdl.h"
#include "zygisk.hpp"

namespace {
constexpr char kLogTag[] = "InlineHookInvalidate";
constexpr char kConfigPath[] = "/data/adb/modules/inline_hook_invalidate/config.txt";
constexpr char kDefaultLibraryName[] = "libart.so";
constexpr std::size_t kMaxConfigBytes = 64 * 1024;

enum class RemapMethod {
    Mmap,
    MmapOnce,
    MprotectPread
};

struct ModuleConfiguration {
    bool enabled = false;
    std::string libraryName = kDefaultLibraryName;
    RemapMethod method = RemapMethod::Mmap;
    std::vector<std::string> targetPackages;
    std::map<std::string, RemapMethod, std::less<>> processModes;
};

std::optional<RemapMethod> parseRemapMethod(const std::string &name) {
    if (name == "mmap") return RemapMethod::Mmap;
    if (name == "mmap-once") return RemapMethod::MmapOnce;
    if (name == "pread") return RemapMethod::MprotectPread;
    return std::nullopt;
}

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

bool parseModuleConfiguration(const std::string &contents, ModuleConfiguration *configuration) {
    if (contents.find('\0') != std::string::npos)
        return false;
    std::istringstream configurationFile(contents);
    std::string firstLine;
    if (!std::getline(configurationFile, firstLine))
        return false;

    firstLine = trimLineEnding(firstLine);

    std::vector<std::string> headerParts = splitOnColon(firstLine);
    if (headerParts.size() > 3 || (headerParts[0] != "0" && headerParts[0] != "1"))
        return false;
    configuration->enabled = headerParts[0] == "1";
    if (headerParts.size() >= 2 && !headerParts[1].empty())
        configuration->libraryName = headerParts[1];
    if (headerParts.size() == 3 && !headerParts[2].empty()) {
        auto method = parseRemapMethod(headerParts[2]);
        if (!method) return false;
        configuration->method = *method;
    }

    std::string line;
    while (std::getline(configurationFile, line)) {
        line = trimLineEnding(line);
        if (line.rfind("@mode ", 0) == 0) {
            std::istringstream directive(line.substr(6));
            std::string process, mode, extra;
            if (!(directive >> process >> mode) || directive >> extra)
                return false;
            auto method = parseRemapMethod(mode);
            if (!method || !configuration->processModes.emplace(process, *method).second)
                return false;
        } else if (!line.empty()) {
            configuration->targetPackages.push_back(line);
        }
    }
    return true;
}

bool readModuleConfiguration(zygisk::Api *api, ModuleConfiguration *configuration) {
    const int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    const int directory = api->getModuleDir();
    const int fd = directory < 0 ? open(kConfigPath, flags) : openat(directory, "config.txt", flags);
    if (directory >= 0)
        close(directory);
    if (fd < 0)
        return false;

    struct stat info{};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 || info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) > kMaxConfigBytes) {
        close(fd);
        return false;
    }

    std::string contents;
    char buffer[1024];
    ssize_t count;
    do {
        count = read(fd, buffer, sizeof(buffer));
        if (count > 0)
            contents.append(buffer, static_cast<std::size_t>(count));
    } while ((count > 0 || (count < 0 && errno == EINTR)) && contents.size() <= kMaxConfigBytes);
    close(fd);
    return count == 0 && parseModuleConfiguration(contents, configuration);
}

std::optional<RemapMethod> selectedMethod(const ModuleConfiguration &configuration, const char *process) {
    for (const auto &target : configuration.targetPackages) {
        if (target == process) {
            auto override = configuration.processModes.find(process);
            return override == configuration.processModes.end() ? configuration.method : override->second;
        }
    }
    return std::nullopt;
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

void runRemap(const std::string &libraryName, RemapMethod method) {
    LocatedLibrary library = locateExecutableSegments(libraryName);
    if (!library.found) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "could not locate executable segments of %s", libraryName.c_str());
        return;
    }

    const int fileDescriptor = open(library.realPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fileDescriptor < 0) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "open failed for %s: %s", library.realPath.c_str(), strerror(errno));
        return;
    }

    const std::int64_t pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0 || (pageSize & (pageSize - 1)) != 0) {
        close(fileDescriptor);
        return;
    }
    const bool once = method == RemapMethod::MmapOnce;
    const bool useMmap = method != RemapMethod::MprotectPread;
    std::vector<ExecutableSegment> monitored;
    std::int32_t initialRemapCount = 0;
    for (ExecutableSegment &segment : library.segments) {
        if (remapSegmentFromDisk(fileDescriptor, segment, pageSize, useMmap)) {
            initialRemapCount++;
            if (!once) {
                segment.expectedChecksum = computeFnv1aChecksum(reinterpret_cast<const void *>(segment.liveAddress), segment.length);
                monitored.push_back(segment);
            }
        }
    }

    if (once || monitored.empty()) {
        close(fileDescriptor);
        if (initialRemapCount == 0)
            __android_log_print(ANDROID_LOG_WARN, kLogTag, "no executable segments remapped for %s", libraryName.c_str());
        else
            __android_log_print(ANDROID_LOG_DEBUG, kLogTag, "one-shot mmap completed for %s (%d segments)", libraryName.c_str(), initialRemapCount);
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag, "remapped %d executable segment(s) of %s from %s using %s, now monitoring continuously", initialRemapCount, libraryName.c_str(), library.realPath.c_str(), useMmap ? "mmap" : "mprotect+pread");
    constexpr std::chrono::milliseconds kPollInterval{100};
    while (true) {
        std::this_thread::sleep_for(kPollInterval);
        for (ExecutableSegment &segment : monitored) {
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

class InlineHookInvalidate : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *moduleApi, JNIEnv *moduleEnvironment) override {
        api = moduleApi;
        environment = moduleEnvironment;
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *arguments) override {
        selected = false;
        configuration = {};
        if (!shouldRun(arguments) || !readModuleConfiguration(api, &configuration) ||
            !configuration.enabled || !methodForProcess(arguments->nice_name)) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        selected = true;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *arguments) override {
        if (!selected)
            return;
        auto method = methodForProcess(arguments->nice_name);
        if (!method) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        if (*method == RemapMethod::MmapOnce) {
            runRemap(configuration.libraryName, *method);
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        std::thread(runRemap, configuration.libraryName, *method).detach();
    }

private:
    bool shouldRun(const zygisk::AppSpecializeArgs *arguments) const {
        return arguments->nice_name != nullptr &&
               !(arguments->is_child_zygote && *arguments->is_child_zygote) &&
               !(api->getFlags() & zygisk::PROCESS_ON_DENYLIST);
    }

    std::optional<RemapMethod> methodForProcess(jstring niceName) const {
        if (niceName == nullptr)
            return std::nullopt;
        const char *processNameCharacters = environment->GetStringUTFChars(niceName, nullptr);
        if (processNameCharacters == nullptr)
            return std::nullopt;

        const auto method = selectedMethod(configuration, processNameCharacters);
        environment->ReleaseStringUTFChars(niceName, processNameCharacters);
        return method;
    }

    zygisk::Api *api = nullptr;
    JNIEnv *environment = nullptr;
    bool selected = false;
    ModuleConfiguration configuration;
};

}

REGISTER_ZYGISK_MODULE(InlineHookInvalidate)
