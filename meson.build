project('ultimate_fuse_system', 'c',
  version: '1.0.0',
  default_options: [
    'c_std=c23', 
    'warning_level=3', 
    'strip=true',
    'b_lundef=false'  # 允许共享库引用主程序导出的公共符号（热插拔模块经 dlopen 解析）
  ]
)

cc = meson.get_compiler('c')

# 选项配置
enable_debug = get_option('enable_debug')
with_asan = get_option('with_asan')
with_ubsan = get_option('with_ubsan')
target_os = get_option('target_os')

# ================= 目标平台定义 =================
if target_os == 'android'
  add_project_arguments('-DTARGET_ANDROID=1', language: 'c')
  target_triplet = 'aarch64-linux-android35'
  if not meson.is_cross_build()
    add_project_arguments('--target=' + target_triplet, language: 'c')
    add_project_link_arguments('--target=' + target_triplet, language: 'c')
  endif
else
  add_project_arguments('-DTARGET_GNU=1', '-D_GNU_SOURCE', language: 'c')
  target_triplet = host_machine.cpu_family() + '-' + host_machine.system()
endif

is_clang = cc.get_id() == 'clang'

# ================= 构建版本水印（sys.log 头 + crash 日志归因） =================
# 每个二进制编译进 NSP_GIT_HASH / NSP_BUILD_MODE / NSP_PROJECT_VERSION，
# 启动时经 nsp_log_build_info() 打进 sys.log，崩溃时 crash_handler 同样打印，
# 使线下 addr2line 可精确对应到提交。无 git 环境回退 unknown（可用
# -Dgit_hash_override=<sha> 手动指定，如 tarball 构建）。
_git_override = get_option('git_hash_override')
_git_prog = find_program('git', required: false)
_git_hash = _git_override
if _git_hash == '' and _git_prog.found()
  _git_hash = run_command(_git_prog, 'rev-parse', '--short', 'HEAD',
                          check: false).stdout().strip()
endif
if _git_hash == ''
  _git_hash = 'unknown'
elif _git_override == '' and _git_prog.found()
  _dirty = run_command(_git_prog, 'diff', '--quiet', check: false)
  if _dirty.returncode() != 0
    _git_hash = _git_hash + '-dirty'
  endif
endif
add_project_arguments('-DNSP_GIT_HASH="' + _git_hash + '"', language: 'c')
add_project_arguments('-DNSP_BUILD_MODE="' + (enable_debug ? 'debug' : 'release') + '"',
                      language: 'c')
add_project_arguments('-DNSP_PROJECT_VERSION="' + meson.project_version() + '"',
                      language: 'c')

# ================= 依赖查找 =================
# libfuse / json-c 按平台隔离，子模块随主项目一起编译（clone 后一键成功）：
#   - android(subproject，默认)：子模块 subprojects/libfuse（master-Android，
#     与 ~/libfuse 同源）NDK 交叉编译 + 子模块 subprojects/json-c（上游 0.19）
#     经 cmake 交叉编译；compat/ 转接头将 <fuse3/...>/<json-c/...> 引用映射
#     到各自平铺头文件布局；
#   - android(prebuilt)：-Dandroid_libfuse=prebuilt / -Dandroid_json_c=prebuilt
#     可分别切回 fuse3_root 预构建静态库；
#   - gnu(system)：系统主线 libfuse3（pkg-config，如本机 3.18.3）；
#   - gnu(custom)：~/libfuse 的 GNU 预构建（~/libfuse-install，3.19.0-rc0，
#     与主线双位兼容：legacy bit31 + 上游 bit37，主线内核下可正常协商），
#     由 -Dlibfuse_source=custom -Dcustom_libfuse_root=<根> 传入，静态链接；
#   - gnu(subproject)：libfuse 用项目内子模块（同 android 子模块路径）；
#   - gnu(auto，默认)：libfuse 系统库优先、缺失回退子模块；
#   - gnu json-c：系统 pkg-config 优先、缺失回退 cmake 子模块（上游即标准，
#     无 ABI 分叉，可直接回退）。
# libcurl（ftp_module，8.21.0+）同样自动处理：gnu 系统优先缺失回退子模块；
# android 默认 cmake 子模块（-Dandroid_curl=prebuilt 切回 -Dcurl_dir 预构建）。
gnu_extra_deps = []
if target_os == 'android'
  fuse3_root = get_option('fuse3_root')
  android_fuse_sp = get_option('android_libfuse') != 'prebuilt'
  android_json_sp = get_option('android_json_c') != 'prebuilt'
  # NDK 根：优先用 -Dandroid_ndk_root 显式传入（scripts/android-build.sh
  # 自动探测后传入）；留空时从交叉编译器路径反推（要求 ini 内为绝对路径，
  # 裸工具名经 PATH 解析时此处只能拿到相对路径，反推失效）。
  # 供 cmake 子项目（json-c/curl）的 Android 平台检测，不硬编码。
  _ndk_opt = get_option('android_ndk_root')
  if _ndk_opt != ''
    _ndk_root = _ndk_opt
  else
    fs_mod = import('fs')
    _ndk_bin = fs_mod.parent(cc.cmd_array()[0])
    _ndk_root = _ndk_bin
    foreach i : range(5)
      _ndk_root = fs_mod.parent(_ndk_root)
    endforeach
  endif
  if android_json_sp
    # Android + json-c 子模块：经 cmake 随主项目交叉编译（静态库、无 apps/
    # tests、-Werror 关闭防 NDK 新警告炸构建；PUBLIC 头文件路径自动透传，
    # <json-c/json.h> 经 compat/json-c 转接头解析）。
    message('json-c: 使用项目内子模块 subprojects/json-c（cmake 交叉编译）')
    json_cmake = import('cmake')
    jsonc_sp = json_cmake.subproject('json-c',
      cmake_options: ['-DBUILD_SHARED_LIBS=OFF', '-DBUILD_STATIC_LIBS=ON',
                      '-DBUILD_APPS=OFF', '-DBUILD_TESTING=OFF',
                      '-DDISABLE_WERROR=ON',
                      '-DANDROID_NDK=' + _ndk_root],
      required: true)
    json_c = jsonc_sp.dependency('json-c')
    json_c_inc = []
  else
    # json-c 静态库+头文件取自 fuse3_root 预构建
    json_c = cc.find_library('json-c', dirs: [fuse3_root + '/lib'], static: true, required: true)
    json_c_inc = include_directories(fuse3_root + '/include')
    message('json-c: 使用预构建静态库 ' + fuse3_root)
  endif
  if not android_fuse_sp
    fuse_inc = include_directories(fuse3_root + '/include')
    fuse_lib = cc.find_library('fuse3', dirs: [fuse3_root + '/lib'], static: true, required: true)
    compat_inc = []
    message('libfuse3: 使用预构建静态库 ' + fuse3_root)
  else
    # Android + 子模块：随主项目一起 NDK 交叉编译（选项与
    # ~/libfuse/build_android.sh 对齐：静态库、无 utils/examples/tests、
    # 无 usdt/io-uring、无 mtab）。注意 both_libraries 无视 default_library，
    # 其 libfuse_dep 默认链 shared——Android 设备无 libfuse3.so，必须显式取
    # 静态库并重组依赖（用法需求经 declare_dependency 透传，与预构建一致）。
    message('libfuse3: 使用项目内子模块 subprojects/libfuse（NDK 交叉编译）')
    fuse3_sp = subproject('libfuse', required: true,
      default_options: ['default_library=static', 'disable-mtab=true',
        'utils=false', 'examples=false', 'tests=false', 'useroot=false',
        'enable-usdt=false', 'enable-io-uring=false'])
    fuse_lib = declare_dependency(
      link_with: fuse3_sp.get_variable('libfuse').get_static_lib(),
      include_directories: fuse3_sp.get_variable('include_dirs'),
      dependencies: [dependency('threads'),
                     cc.find_library('dl', required: false)])
    fuse_inc = []
    compat_inc = include_directories('compat')
  endif
else
  libfuse_source = get_option('libfuse_source')
  if libfuse_source == 'custom'
    # GNU + 定制库：头文件与静态库均取自预构建根（如 ~/libfuse-install）；
    # 定制库启用 io-uring，静态链接需补 liburing（见其 fuse3.pc Requires.private）
    custom_libfuse_root = get_option('custom_libfuse_root')
    if custom_libfuse_root == ''
      error('GNU + libfuse_source=custom 需要 -Dcustom_libfuse_root=<根>（如 ~/libfuse-install，含 include/ 与 lib/）')
    endif
    fuse_inc = include_directories(custom_libfuse_root + '/include')
    fuse_lib = cc.find_library('fuse3', dirs: [custom_libfuse_root + '/lib'],
                               static: true, required: true)
    gnu_extra_deps = [dependency('liburing', required: true)]
    compat_inc = []
    message('libfuse3: 使用定制预构建 ' + custom_libfuse_root)
  else
    if libfuse_source == 'system'
      fuse3_sys_dep = dependency('fuse3', version: '>=3.6', required: true)
    else
      # auto：系统库优先、缺失回退子模块；subproject：强制子模块（仍探测
      # 系统库版本号用于日志，但不用它）
      fuse3_sys_dep = dependency('fuse3', version: '>=3.6', required: false)
    endif
    if libfuse_source != 'subproject' and fuse3_sys_dep.found()
      # GNU + 系统库：系统 pkg-config 主线 libfuse3
      message('libfuse3: 使用系统 pkg-config')
      fuse_inc = []
      fuse_lib = fuse3_sys_dep
      compat_inc = []
    else
      if libfuse_source == 'system'
        error('未找到系统 libfuse3（pkg-config），请安装 libfuse3-dev，或改用 -Dlibfuse_source=auto/subproject/custom')
      endif
      # GNU + 子模块：随主项目一起编译（libfuse 自带的 utils/examples/tests
      # 与主项目无关，一键构建时关闭，只取 libfuse_dep）
      message('libfuse3: 使用项目内子模块 subprojects/libfuse')
      fuse3_sp = subproject('libfuse', required: true,
        default_options: ['utils=false', 'examples=false', 'tests=false'])
      fuse_lib = fuse3_sp.get_variable('libfuse_dep')
      fuse_inc = []
      compat_inc = include_directories('compat')
    endif
  endif

  # 系统 json-c 优先，缺失回退 cmake 子模块
  json_c_sys = dependency('json-c', required: false)
  if json_c_sys.found()
    message('json-c: 使用系统 pkg-config')
    json_c = json_c_sys
  else
    message('json-c: 使用项目内子模块 subprojects/json-c（cmake 编译）')
    json_cmake = import('cmake')
    jsonc_sp = json_cmake.subproject('json-c',
      cmake_options: ['-DBUILD_SHARED_LIBS=OFF', '-DBUILD_STATIC_LIBS=ON',
                      '-DBUILD_APPS=OFF', '-DBUILD_TESTING=OFF',
                      '-DDISABLE_WERROR=ON'],
      required: true)
    json_c = jsonc_sp.dependency('json-c')
    compat_inc = include_directories('compat')
  endif
endif

# 自动探测 libiconv
libiconv = cc.find_library('iconv', required: false)

# 项目通用依赖
project_deps = [
  dependency('threads'),
  fuse_lib,
  libiconv,
  json_c
] + gnu_extra_deps

# ================= 编译标志 =================
opt_flags = []
link_flags = []

# 定义需要屏蔽的标准兼容警告
disable_warnings = [
  '-Wno-gnu-zero-variadic-macro-arguments',
  '-Wno-variadic-macro-arguments-omitted',
  '-Wno-unused-parameter'
]

if enable_debug
    # sanitizer 必须同时进**编译**与**链接**：只进 link_flags 会「链接了运行时
    # 但一个函数都没插桩」——内存验收会给出错误安全感（旧实现即此缺陷）。
    # 推荐写法：-Db_sanitize=address,undefined（Meson 内建，自动双端生效）；
    # 本项目的 with_asan/with_ubsan 与之等价，二选一即可（重复叠加无害）。
    sanitize_flags = (with_asan ? ['-fsanitize=address'] : []) + \
                     (with_ubsan ? ['-fsanitize=undefined'] : [])
    opt_flags = ['-O0', '-g3', '-ggdb3', '-fno-omit-frame-pointer', '-fstack-protector-all', '-DDEBUG=1', '-DNSP_ENABLE_IO_LOG'] + sanitize_flags + disable_warnings
    link_flags = sanitize_flags
else
    if with_asan or with_ubsan
        warning('with_asan/with_ubsan 仅在 -Denable_debug=true 下生效（当前为 release，已忽略）')
    endif
    opt_flags = ['-O3', '-flto', '-fstack-protector-strong', '-ffunction-sections', '-fdata-sections'] + disable_warnings
    # Clang 特有优化
    if is_clang
        opt_flags += ['-mllvm', '-unroll-threshold=128']
    endif
    # -Dstrip=false（如符号包 build_android_sym）时不剥离，保留 addr2line 可用符号
    link_flags = (get_option('strip') ? ['-Wl,-s'] : []) + ['-Wl,--gc-sections']
endif

# 将所有 flags 应用到项目
add_project_arguments(opt_flags, language: 'c')
add_project_link_arguments(link_flags, language: 'c')

# ================= 项目头文件路径 =================
inc_dir = include_directories('include')
if target_os == 'android'
  if get_option('android_libfuse') == 'prebuilt'
    all_inc_dirs = [fuse_inc, inc_dir]
    if get_option('android_json_c') != 'prebuilt'
      # libfuse 预构建 + json-c 子模块：compat/ 只为 <json-c/json.h> 转接头
      all_inc_dirs += include_directories('compat')
    endif
  else
    # Android + 子模块：预构建根（若启用）只提供 json-c 头文件，compat/
    # 转接头将 <fuse3/...>/<json-c/...> 映射到子模块平铺头文件
    all_inc_dirs = [json_c_inc, inc_dir, compat_inc]
  endif
elif get_option('libfuse_source') == 'custom'
  # GNU + 定制库：定制头文件优先，保证 <fuse3/...> 解析到预构建根；
  # json-c 回退子模块时追加 compat/ 转接头
  all_inc_dirs = [fuse_inc, inc_dir, compat_inc]
else
  # GNU + 系统库/子模块：子模块构建时追加 compat/ 转接头
  all_inc_dirs = [inc_dir, compat_inc]
endif

# ================= 源码集合 =================
# 契约：common_sources 被多个二进制逐源重编译（Meson 正常行为，非错误）。
# 规则引擎已内建（fw_rules.c 随 fuse_daemon 编译，唯一的规则语义实现）——
# 修改 trie/变量静态性时跑 tests/test_rules.py 与 tests/test_path_vars.py。
common_sources = [
    'src/core/common.c',
    'src/core/build_info.c',
    'src/core/path_trie.c',
    'src/config/config_parser.c',
    'src/config/path_vars.c',
    'src/core/fast_search.c',
    'src/core/uid_map.c',
    'src/core/sys_pkg.c'
]

fuse_daemon_sources = ['src/daemon/fuse_daemon.c', 'src/daemon/fw_config.c', 'src/daemon/fw_pkg.c', 'src/daemon/fw_rules.c', 'src/daemon/fd_close_queue.c', 'src/daemon/cfg_watch.c', 'src/core/crash_dump.c', 'src/core/build_info.c', 'src/core/fast_pid.c', 'src/module/loader.c', 'src/module/fault_fence.c', 'src/module/module_guard.c',
  # 配置**读取**在框架侧完成（文件 I/O + inotify + 词法/段头识别，产出扁平视图
  # 经 fw_config 下发给模块），模块不再自行读文件。框架另建一份 AppConfig 索引
  # （config_build_from_view），但只用于回答 MONITOR 的三层合并——它是配置开关，
  # 不得随规则模块的可用性一起失效（fw_pkg.c 提供其 uid→包名输入）；路径决策
  # （REDIRECT/HIDE/RO）仍由模块自己的索引决定。
  'src/config/config_parser.c', 'src/config/path_vars.c', 'src/core/path_trie.c',
  'src/core/fast_search.c', 'src/core/uid_map.c', 'src/core/sys_pkg.c',
  # pthread_create 截持：libfuse worker 默认命名 fuse_worker（见文件头），
  # 仅 fuse_daemon 编入（injector/log_monitor 自有线程均已自命名，无需截持）
  'src/daemon/fuse_thread_naming.c']
injector_sources = ['src/injector/injector.c', 'src/injector/inject_target.c', 'src/injector/mount_manager.c', 'src/injector/ipc_server.c', 'src/injector/config_publisher.c', 'src/injector/ns_utils.c', 'src/injector/ns_global_replace.c', 'src/injector/reaped_managed.c', 'src/core/fast_pid.c']

# ================= 构建可执行文件 =================
install_bin_dir = 'bin'

# fuse_daemon：纯框架（回调骨架 + 模块调度 + 存储原语），不链接规则引擎源，
# 规则能力来自 dlopen 的热插拔模块（basic_rules.so 等）；common.c 为公共工具（日志/路径）。

# nsp_util 轻量公共库（纯 libc，无项目全局依赖）：收敛 UDS 抽象地址填充、send_all
# 全量发送、str_trim、mkdir_p、daemonize、cgroup 逃逸，供各二进制与热插拔模块
# 复用（rule_server 等未链接 common.c 的目标亦可直接用，避免私刻副本漂移）
nsp_util_lib = static_library('nsp_util',
  'src/core/nsp_util.c',
  include_directories: all_inc_dirs,
)
nsp_util_dep = declare_dependency(link_with: nsp_util_lib,
                                  include_directories: all_inc_dirs)

# nsp_comm 统一通讯线程（epoll: eventfd+timerfd）：无锁/短临界区 outbox +
# 后端 emit 表。调用线程只 nsp_comm_post，永不阻塞；各二进制按需 register。
nsp_comm_lib = static_library('nsp_comm',
  'src/core/nsp_comm.c',
  include_directories: all_inc_dirs,
)
nsp_comm_dep = declare_dependency(link_with: nsp_comm_lib,
                                  include_directories: all_inc_dirs)

# nsp_rule_file 规则配置文件行级读写（纯 libc，零项目全局依赖）：合并
# log_ctl 与 rule_server 中两份逐字同构的私有行数组原语与段编辑逻辑，
# 语义基准取 rule_server（权威控制面）。两处编辑同一个 injector.conf，
# 共享后落盘一律原子写，避免 inotify 监听端读到半截配置。
nsp_rule_file_lib = static_library('nsp_rule_file',
  'src/core/nsp_rule_file.c',
  include_directories: all_inc_dirs,
)
nsp_rule_file_dep = declare_dependency(link_with: nsp_rule_file_lib,
                                       include_directories: all_inc_dirs)

# INI 文件编辑仅由 rule_server 使用，不属于模块 V2 运行时 ABI。
nsp_ini_store_lib = static_library('nsp_ini_store',
  'src/core/nsp_ini_store.c',
  include_directories: all_inc_dirs,
  dependencies: nsp_util_dep,
)
nsp_ini_store_dep = declare_dependency(link_with: nsp_ini_store_lib,
                                       dependencies: nsp_util_dep)

executable('fuse_daemon',
  fuse_daemon_sources + ['src/core/common.c'],
  include_directories: all_inc_dirs,
  # libdl：fuse_thread_naming 经 dlsym(RTLD_NEXT) 取真实 pthread_create
  #（bionic 自带，GNU 经此显式链接；required=false 兼容无独立 libdl 的工具链）
  dependencies: project_deps + [nsp_util_dep, nsp_comm_dep,
                                cc.find_library('dl', required: false)],
  c_args: ['-DFUSE_USE_VERSION=317'],
  link_args: ['-Wl,--export-dynamic'],  # 导出公共符号，供 dlopen 的热插拔模块解析
  install: true,
  install_dir: install_bin_dir
)

if target_os == 'android'
  executable('injector',
    injector_sources + common_sources,
    include_directories: all_inc_dirs,
    dependencies: project_deps + [nsp_util_dep, nsp_comm_dep],
    install: true,
    install_dir: install_bin_dir
  )
else
  # injector GNU 测试目标（test-only，不 install）：injector 本体只随 Android 模块
  # 分发，但同一份源码在 GNU 下可编译，供 tests/test_inject_mount_env.py 在 rootless
  # 容器沙箱（unshare user+mount+pid ns）里真实跑挂载/卸载流程。Android 分支不改动。
  executable('injector',
    injector_sources + common_sources,
    include_directories: all_inc_dirs,
    dependencies: project_deps + [nsp_util_dep, nsp_comm_dep],
    install: false
  )
  # 全局替换式挂载方案测试驱动（仅 GNU 构建）：injector 本体仅 Android 交叉构建，
  # GNU 测试无法直接运行它；本驱动链接 ns_utils 的全局替换原语并以 CLI 暴露，
  # 供 tests/test_global_replace.py 在私有挂载命名空间中模拟安卓视图验证。
  executable('global_replace_ctl',
    ['src/injector/global_replace_ctl.c', 'src/injector/ns_utils.c', 'src/injector/ns_global_replace.c',
     'src/injector/inject_target.c', 'src/injector/mount_manager.c',
      'src/core/fast_pid.c'] + common_sources,
    include_directories: all_inc_dirs,
    dependencies: project_deps + [nsp_util_dep, nsp_comm_dep],
    install: false
  )
endif

executable('log_monitor',
  ['src/log/log_monitor.c'] + common_sources,
  include_directories: all_inc_dirs,
  dependencies: project_deps + [nsp_util_dep, nsp_comm_dep],
  install: true,
  install_dir: install_bin_dir
)

executable('log_ctl',
  ['src/log/log_ctl.c'] + common_sources,
  include_directories: all_inc_dirs,
  dependencies: project_deps + [nsp_util_dep, nsp_comm_dep, nsp_rule_file_dep],
  install: true,
  install_dir: install_bin_dir
)

# rule_server：规则控制守护进程（前端经 nsp_rule_socket 抽象 UDS 以 JSON 行协议
# 动态增删/启停规则、重载配置、停止注入，还管 ftp.conf 服务器账号）。
# 纯文件级操作，仅依赖 json-c，不链接 libfuse3；Android/GNU 均构建
# （路径经 CONFIG_DIR 宏适配）。INI 编辑由私有静态库提供。
# 日志统一走 comm 线程（common.c 的 log_init/log_internal，sys.log 显 [rule_server]），
# 与 injector/fuse_daemon 同通道，不再各写 stderr。
executable('rule_server',
  ['src/rule/rule_server.c', 'src/core/common.c',
   'src/core/build_info.c'],
  include_directories: all_inc_dirs,
  dependencies: [json_c, dependency('threads'), nsp_util_dep, nsp_comm_dep, nsp_rule_file_dep, nsp_ini_store_dep],
  install: true,
  install_dir: install_bin_dir
)

# ================= 热插拔模块 =================
# V4 起模块只剩「后端存储提供者」形态：规则决策引擎已编入 fuse_daemon
# （src/daemon/fw_rules.c），故不再有 basic_rules.so。

# ftp_module：FTP 存储后端模块（BACKEND 类型，dlopen 共享库，无 FUSE 实现）。
# 使用 libcurl（8.21.0+）处理所有 FTP 协议操作，模块仅负责转发。
ftp_module_sources = [
    'src/modules/ftp/ftp_module.c',
    'src/modules/ftp/ftp_conf.c',
    'src/modules/ftp/ftp_mux.c',
    'src/modules/ftp/ftp_backend_libcurl.c',
]

# ftp_module：FTP 存储后端模块（BACKEND 类型，dlopen 共享库，无 FUSE 实现）。
# libcurl（8.21.0+）默认经子模块自动构建，无需手动指定：
#   - gnu：系统 pkg-config（版本门槛 >=8.21.0）优先，缺失回退 cmake 子模块
#    （pin curl-8_22_0，门槛天然满足）；
#   - android(subproject，默认)：cmake 子模块随主项目交叉编译（静态库，
#     仅 FTP+HTTP、无 SSL 及可选外部依赖，CURL::libcurl 别名透传头文件）；
#   - android(prebuilt)：-Dandroid_curl=prebuilt 切回 -Dcurl_dir 预构建。
# 最小构建集与 ftp 代码用法对齐（只用明文 FTP，CURLOPT_USE_SSL=CURLUSESSL_NONE；
# 认证/代理/MIME/NETRC 保持默认，禁掉的均为未引用协议与特性——误禁会在
# 编译期以 CURLE_NOT_BUILT_IN 相关符号缺失暴露，而非静默降级）。
curl_cmake_opts = ['-DBUILD_SHARED_LIBS=OFF', '-DBUILD_STATIC_LIBS=ON',
  '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
  '-DBUILD_CURL_EXE=OFF', '-DBUILD_TESTING=OFF',
  '-DCURL_DISABLE_INSTALL=ON',
  '-DCURL_ENABLE_SSL=OFF',
  '-DCURL_ZLIB=OFF', '-DCURL_BROTLI=OFF', '-DCURL_ZSTD=OFF',
  '-DUSE_NGHTTP2=OFF', '-DUSE_LIBIDN2=OFF',
  '-DCURL_USE_LIBPSL=OFF', '-DCURL_USE_LIBSSH2=OFF',
  '-DCURL_DISABLE_DICT=ON', '-DCURL_DISABLE_FILE=ON',
  '-DCURL_DISABLE_GOPHER=ON', '-DCURL_DISABLE_IMAP=ON',
  '-DCURL_DISABLE_LDAP=ON', '-DCURL_DISABLE_MQTT=ON',
  '-DCURL_DISABLE_POP3=ON', '-DCURL_DISABLE_RTSP=ON',
  '-DCURL_DISABLE_SMTP=ON', '-DCURL_DISABLE_TELNET=ON',
  '-DCURL_DISABLE_TFTP=ON', '-DCURL_DISABLE_WEBSOCKETS=ON',
  '-DCURL_DISABLE_IPFS=ON', '-DCURL_DISABLE_DOH=ON',
  '-DCURL_DISABLE_ALTSVC=ON', '-DCURL_DISABLE_HEADERS_API=ON',
  '-DCURL_DISABLE_HSTS=ON']

if target_os == 'gnu'
  ftp_curl_dep = dependency('libcurl', version: '>=8.21.0', required: false)
  if ftp_curl_dep.found()
    message('libcurl: 使用系统 pkg-config')
  else
    # GNU + curl 子模块：经 cmake 随主项目编译（静态库，见上；取实 target
    # libcurl_static——cmake ALIAS 不在 meson target 列表，见构建验证）
    message('libcurl: 使用项目内子模块 subprojects/curl（cmake 编译）')
    curl_cmake = import('cmake')
    curl_sp = curl_cmake.subproject('curl',
      cmake_options: curl_cmake_opts, required: true)
    ftp_curl_dep = curl_sp.dependency('libcurl_static')
  endif
  ftp_curl_inc = []
else
  if get_option('android_curl') == 'prebuilt'
    curl_root = get_option('curl_dir')
    if curl_root == ''
      error('android_curl=prebuilt 需要 -Dcurl_dir=<根目录>（含 lib/.libs/libcurl.a 与 include/，如 ~/curl-8.21.0）')
    endif
    curl_a_dir = curl_root + '/lib/.libs'
    curl_inc_dir = curl_root + '/include'
    ftp_curl_dep = meson.get_compiler('c').find_library('curl',
      dirs: [curl_a_dir], required: true, static: true)
    ftp_curl_inc = include_directories(curl_inc_dir)
    # 编译期校验：确认预构建 libcurl 头文件含代码使用的新 API
    # （CURLINFO_CONTENT_LENGTH_DOWNLOAD_T，curl >= 7.55.0），防止误用旧库
    if not meson.get_compiler('c').has_header_symbol('curl/curl.h',
        'CURLINFO_CONTENT_LENGTH_DOWNLOAD_T', include_directories: ftp_curl_inc)
      error('预构建 libcurl（' + curl_root + '）头文件缺少 CURLINFO_CONTENT_LENGTH_DOWNLOAD_T，请确认使用 curl >= 8.21.0')
    endif
    message('libcurl: 使用预构建静态库 ' + curl_root)
  else
    message('libcurl: 使用项目内子模块 subprojects/curl（cmake 交叉编译）')
    curl_cmake = import('cmake')
    curl_sp = curl_cmake.subproject('curl',
      cmake_options: curl_cmake_opts + ['-DANDROID_NDK=' + _ndk_root],
      required: true)
    ftp_curl_dep = curl_sp.dependency('libcurl_static')
    ftp_curl_inc = []
  endif
endif

shared_library('ftp_module',
  ftp_module_sources,
  include_directories: [all_inc_dirs, ftp_curl_inc],
  dependencies: [dependency('threads'), ftp_curl_dep, cc.find_library('dl', required: false), nsp_util_dep],
  c_args: ['-DNSP_MODULE_BUILD'],  # 模块独立 ABI：仅模块激活 nsp_module.h 运行时段
  name_prefix: '',
  install: true,
  install_dir: install_bin_dir + '/modules/ftp_module'
)

# 模块规则类型注册文件：rule_server 扫描合并动态规则类型（格式见 nsp_module.h）
install_data('src/modules/ftp/ftp_module.rules',
  install_dir: install_bin_dir + '/modules/ftp_module'
)

# ================= Zygisk 应用创建通知模块（仅 Android，双 ABI） =================
# 新应用经 preAppSpecialize → companion → nsp_ipc_socket 通知 injector，
# injector 收到后转入被动模式停止周期扫描（src/injector/ipc_server.c）。
if target_os == 'android'
  subdir('src/zygisk')
endif

# ================= 测试 =================
# 测试流程由 Python 脚本完成（tests/ 目录），详见 AGENTS.md“测试流程”
message('========================================')
message('构建配置信息:')
message('  目标平台: ' + target_os)
message('  CPU/系统: ' + target_triplet)
message('  Debug 模式: ' + (enable_debug ? '启用' : '禁用'))
message('========================================')
