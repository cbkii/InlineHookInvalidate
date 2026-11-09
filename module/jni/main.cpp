#include <android/log.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <link.h>
#include <map>
#include <memory>
#include <new>
#include <pthread.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
            if (programHeader.p_type != PT_LOAD || programHeader.p_flags != (PF_R | PF_X) ||
                programHeader.p_filesz == 0 || programHeader.p_filesz != programHeader.p_memsz)
                continue;

            ExecutableSegment segment;
            const auto base = reinterpret_cast<std::uintptr_t>(libraryInfo.dli_fbase);
            if (programHeader.p_vaddr > std::numeric_limits<std::uintptr_t>::max() - base)
                continue;
            segment.liveAddress = base + programHeader.p_vaddr;
            segment.fileOffset = programHeader.p_offset;
            segment.length = programHeader.p_filesz;
            result.segments.push_back(segment);
        }
        result.found = !result.segments.empty();
    }

    xdl_close(libraryHandle);
    return result;
}

struct PageRange {
    std::uintptr_t address;
    std::size_t length;
    off_t offset;
    std::size_t prefix;
};

std::optional<PageRange> pageRange(const ExecutableSegment &segment, std::size_t pageSize,
                                   const struct stat &source) {
    const auto mask = pageSize - 1;
    const auto prefix = segment.liveAddress & mask;
    const auto address = segment.liveAddress - prefix;
    const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
    if (segment.length == 0 || source.st_size < 0 ||
        segment.fileOffset > static_cast<std::uintmax_t>(source.st_size) ||
        segment.length > static_cast<std::uintmax_t>(source.st_size) - segment.fileOffset ||
        (segment.fileOffset & mask) != prefix ||
        segment.length > maxAddress - segment.liveAddress ||
        mask > maxAddress - segment.liveAddress - segment.length)
        return std::nullopt;
    const auto length = ((segment.liveAddress + segment.length + mask) & ~mask) - address;
    return PageRange{address, length, static_cast<off_t>(segment.fileOffset - prefix), prefix};
}

bool matchesSourceMapping(const PageRange &range, const struct stat &source) {
    std::ifstream maps("/proc/self/maps");
    std::uintptr_t next = range.address;
    const std::uintptr_t end = next + range.length;
    std::string line;
    while (next < end && std::getline(maps, line)) {
        std::uintptr_t start, stop;
        std::uintmax_t offset, inode;
        unsigned int deviceMajor, deviceMinor;
        char permissions[5];
        if (std::sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxMAX " %x:%x %" SCNuMAX,
                        &start, &stop, permissions, &offset, &deviceMajor, &deviceMinor, &inode) != 7 ||
            stop <= next)
            continue;
        if (start > next || std::strcmp(permissions, "r-xp") != 0 ||
            deviceMajor != major(source.st_dev) || deviceMinor != minor(source.st_dev) ||
            inode != static_cast<std::uintmax_t>(source.st_ino) ||
            offset + (next - start) != static_cast<std::uintmax_t>(range.offset) + (next - range.address))
            return false;
        next = stop;
    }
    return next >= end;
}

bool restoreSegment(int fd, ExecutableSegment &segment, std::size_t pageSize,
                    const struct stat &source, bool useMmap, bool continuous) {
    auto range = pageRange(segment, pageSize, source);
    if (!range || !matchesSourceMapping(*range, source))
        return false;
    // Stage the source before changing any executable mapping.
    void *disk = mmap(nullptr, range->length, PROT_READ, MAP_PRIVATE, fd, range->offset);
    if (disk == MAP_FAILED)
        return false;
    const auto *bytes = static_cast<const char *>(disk) + range->prefix;
    auto *live = reinterpret_cast<char *>(segment.liveAddress);
    auto *page = reinterpret_cast<void *>(range->address);
    bool success = true;
    if (std::memcmp(live, bytes, segment.length) != 0) {
        if (useMmap) {
            success = mmap(page, range->length, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
                           fd, range->offset) != MAP_FAILED;
        } else if (mprotect(page, range->length, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            std::memcpy(live, bytes, segment.length);
            __builtin___clear_cache(live, live + segment.length);
            success = mprotect(page, range->length, PROT_READ | PROT_EXEC) == 0;
            if (!success) {
                __android_log_print(ANDROID_LOG_ERROR, kLogTag, "could not restore RX protection, trying file mapping");
                success = mmap(page, range->length, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
                               fd, range->offset) != MAP_FAILED;
            }
        } else {
            success = false;
        }
    }
    if (success && continuous)
        segment.expectedChecksum = computeFnv1aChecksum(bytes, segment.length);
    munmap(disk, range->length);
    return success;
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

    const long pageSize = sysconf(_SC_PAGESIZE);
    struct stat source{};
    if (pageSize <= 0 || (pageSize & (pageSize - 1)) != 0 ||
        fstat(fileDescriptor, &source) != 0 || !S_ISREG(source.st_mode)) {
        close(fileDescriptor);
        return;
    }
    const bool once = method == RemapMethod::MmapOnce;
    const bool useMmap = method != RemapMethod::MprotectPread;
    std::vector<ExecutableSegment> monitored;
    monitored.reserve(library.segments.size());
    std::int32_t initialRemapCount = 0;
    for (ExecutableSegment &segment : library.segments) {
        if (restoreSegment(fileDescriptor, segment, pageSize, source, useMmap, !once)) {
            initialRemapCount++;
            if (!once) monitored.push_back(segment);
        }
    }

    if (static_cast<std::size_t>(initialRemapCount) != library.segments.size())
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "skipped one or more unsupported or unreadable executable segments");
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
    while (!monitored.empty()) {
        std::this_thread::sleep_for(kPollInterval);
        for (auto it = monitored.begin(); it != monitored.end();) {
            // The ART library lives for the app process lifetime. Other
            // libraries may unload, so confirm their mapping before reading.
            if (libraryName != kDefaultLibraryName) {
                auto range = pageRange(*it, pageSize, source);
                if (!range || !matchesSourceMapping(*range, source)) {
                    it = monitored.erase(it);
                    continue;
                }
            }
            auto liveChecksum = computeFnv1aChecksum(reinterpret_cast<const void *>(it->liveAddress), it->length);
            if (liveChecksum != it->expectedChecksum &&
                !restoreSegment(fileDescriptor, *it, pageSize, source, useMmap, true)) {
                __android_log_print(ANDROID_LOG_WARN, kLogTag, "stopped monitoring an executable segment after restore failed");
                it = monitored.erase(it);
            } else {
                ++it;
            }
        }
    }
    close(fileDescriptor);
}

struct RemapWorker {
    std::string library;
    RemapMethod method;
};

bool startRemapWorker(std::string &library, RemapMethod method) {
    std::unique_ptr<RemapWorker> worker(new (std::nothrow) RemapWorker{std::move(library), method});
    if (!worker) return false;
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0) return false;
    pthread_t thread;
    int error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (error == 0) {
        auto *argument = worker.release();
        error = pthread_create(&thread, &attributes, [](void *data) -> void * {
            std::unique_ptr<RemapWorker> work(static_cast<RemapWorker *>(data));
            runRemap(work->library, work->method);
            return nullptr;
        }, argument);
        if (error != 0) worker.reset(argument);
    }
    pthread_attr_destroy(&attributes);
    return error == 0;
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
        if (!startRemapWorker(configuration.libraryName, *method)) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag, "could not start remap worker");
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
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
