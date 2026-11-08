#include <cassert>
#include <cstdlib>

#include "../module/jni/main.cpp"

namespace {
zygisk::internal::module_abi *module;
std::string configDir;
unsigned unloadRequests;
unsigned libraryLookups;
uint32_t flags;
xdl_info_t fakeLibrary{};

void writeConfig(const char *content, mode_t mode = 0600) {
    const auto path = configDir + "/config.txt";
    unlink(path.c_str());
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, content, strlen(content)) == static_cast<ssize_t>(strlen(content)));
    assert(fchmod(fd, mode) == 0);
    assert(close(fd) == 0);
}
}

void *xdl_open(const char *, int) {
    ++libraryLookups;
    return fakeLibrary.dli_fname ? &fakeLibrary : nullptr;
}
int xdl_info(void *handle, int request, void *result) {
    assert(handle == &fakeLibrary && request == XDL_DI_DLINFO);
    *static_cast<xdl_info_t *>(result) = fakeLibrary;
    return 0;
}
void *xdl_close(void *) { return nullptr; }

int main() {
    char directory[] = "/tmp/ihi-test.XXXXXX";
    assert(mkdtemp(directory));
    configDir = directory;

    JNINativeInterface_ jni{};
    jni.GetStringUTFChars = [](JNIEnv *, jstring string, jboolean *) {
        return reinterpret_cast<const char *>(string);
    };
    jni.ReleaseStringUTFChars = [](JNIEnv *, jstring, const char *) {};
    JNIEnv env{&jni};

    zygisk::internal::api_table table{};
    table.registerModule = [](auto *, auto *abi) { module = abi; return true; };
    table.setOption = [](void *, zygisk::Option option) {
        assert(option == zygisk::DLCLOSE_MODULE_LIBRARY);
        ++unloadRequests;
    };
    table.getFlags = [](void *) { return flags; };
    table.getModuleDir = [](void *) { return open(configDir.c_str(), O_RDONLY | O_DIRECTORY); };
    zygisk_module_entry(&table, &env);

    jint uid = 10001, gid = 10001, runtime = 0, mount = 0;
    jintArray gids = nullptr;
    jobjectArray rlimits = nullptr;
    jstring se = nullptr, name = nullptr, instruction = nullptr, data = nullptr;
    jboolean child = false;
    zygisk::AppSpecializeArgs args{uid, gid, gids, runtime, rlimits, mount, se, name,
                                  instruction, data, nullptr, &child, nullptr,
                                  nullptr, nullptr, nullptr, nullptr};

    auto runApp = [&](const char *process, bool remap) {
        name = process;
        unloadRequests = libraryLookups = 0;
        module->preAppSpecialize(module->impl, &args);
        assert(unloadRequests == (remap ? 0u : 1u));
        assert(libraryLookups == 0);
        module->postAppSpecialize(module->impl, &args);
        assert(unloadRequests == 1);
        assert(libraryLookups == (remap ? 1u : 0u));
    };

    ModuleConfiguration config;
    assert(parseModuleConfiguration("1:libart.so\r\ncom.example\r\n", &config));
    assert(config.enabled && config.method == RemapMethod::Mmap);
    assert(targetListContainsProcess(config.targetPackages, "com.example"));
    assert(!targetListContainsProcess(config.targetPackages, "com.example:remote"));
    assert(parseModuleConfiguration("1:libart.so:pread\n", &config));
    assert(config.method == RemapMethod::MprotectPread);
    assert(!parseModuleConfiguration("1:libart.so:unknown\n", &config));

    runApp("com.example", false); // Missing config
    writeConfig("0:libart.so:mmap-once\ncom.example\n");
    runApp("com.example", false);
    writeConfig("1:libart.so:mmap-once\ncom.example\n", 0666);
    runApp("com.example", false);
    writeConfig("1:libart.so:mmap-once\ncom.example\n");
    runApp(nullptr, false);
    runApp("com.example:remote", false);
    child = true;
    runApp("com.example", false);
    child = false;
    flags = zygisk::PROCESS_ON_DENYLIST;
    runApp("com.example", false);
    flags = 0;
    runApp("com.example", true); // Missing library still unloads

    // Exercise the successful mmap path without modifying a running library.
    const auto path = configDir + "/test.so";
    writeConfig("1:libart.so:mmap-once\ncom.example\n");
    const auto pageSize = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    std::string fileBytes(pageSize, 'A');
    const int fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, fileBytes.data(), pageSize) == static_cast<ssize_t>(pageSize));
    auto *page = static_cast<char *>(mmap(nullptr, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
    assert(page != MAP_FAILED && close(fd) == 0);
    *page = 'B';
    assert(mprotect(page, pageSize, PROT_READ | PROT_EXEC) == 0);
    ElfW(Phdr) header{};
    header.p_type = PT_LOAD;
    header.p_flags = PF_R | PF_X;
    header.p_filesz = header.p_memsz = pageSize;
    fakeLibrary.dli_fname = path.c_str();
    fakeLibrary.dli_fbase = page;
    fakeLibrary.dlpi_phdr = &header;
    fakeLibrary.dlpi_phnum = 1;
    runApp("com.example", true);
    assert(*page == 'A');
    assert(munmap(page, pageSize) == 0 && unlink(path.c_str()) == 0);

    unloadRequests = 0;
    module->preServerSpecialize(module->impl, nullptr);
    assert(unloadRequests == 1);
    unlink((configDir + "/config.txt").c_str());
    assert(rmdir(configDir.c_str()) == 0);
}
