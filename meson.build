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

# ================= 依赖查找 =================
if target_os == 'android'
  fuse3_root = get_option('fuse3_root')
  fuse_inc = include_directories(fuse3_root + '/include')
  fuse_lib = cc.find_library('fuse3', dirs: [fuse3_root + '/lib'], static: true, required: true)

  # json-c 静态库
  json_c = cc.find_library('json-c', dirs: [fuse3_root + '/lib'], static: true, required: true)
else
  # 主线 libfuse3: 使用 pkg-config 或系统库
  fuse3_dep = dependency('fuse3', version: '>=3.0', required: true)
  fuse_inc = []
  fuse_lib = fuse3_dep

  # 系统 json-c
  json_c = dependency('json-c', required: true)
endif

# 自动探测 libiconv
libiconv = cc.find_library('iconv', required: false)

# 项目通用依赖
project_deps = [
  dependency('threads'),
  fuse_lib,
  libiconv,
  json_c
]

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
    opt_flags = ['-O0', '-g3', '-ggdb3', '-fno-omit-frame-pointer', '-fstack-protector-all', '-DDEBUG=1'] + disable_warnings
    link_flags = (with_asan ? ['-fsanitize=address'] : []) + (with_ubsan ? ['-fsanitize=undefined'] : [])
else
    opt_flags = ['-O3', '-flto', '-fstack-protector-strong', '-ffunction-sections', '-fdata-sections'] + disable_warnings
    # Clang 特有优化
    if is_clang
        opt_flags += ['-mllvm', '-unroll-threshold=128']
    endif
    link_flags = ['-Wl,-s', '-Wl,--gc-sections']
endif

# 将所有 flags 应用到项目
add_project_arguments(opt_flags, language: 'c')
add_project_link_arguments(link_flags, language: 'c')

# ================= 项目头文件路径 =================
inc_dir = include_directories('include')
if target_os == 'android'
  all_inc_dirs = [fuse_inc, inc_dir]
else
  all_inc_dirs = inc_dir
endif

# ================= 源码集合 =================
common_sources = [
    'src/core/common.c',
    'src/core/path_trie.c',
    'src/config/config_parser.c',
    'src/config/path_vars.c',
    'src/core/fast_search.c',
    'src/core/uid_map.c'
]

fuse_daemon_sources = ['src/daemon/fuse_daemon.c', 'src/core/crash_dump.c', 'src/core/fast_pid.c', 'src/module/loader.c']
injector_sources = ['src/injector/injector.c', 'src/injector/inject_target.c', 'src/injector/mount_manager.c', 'src/injector/ipc_server.c', 'src/injector/config_publisher.c', 'src/injector/ns_utils.c', 'src/core/fast_pid.c']

# ================= 构建可执行文件 =================
install_bin_dir = 'bin'

# fuse_daemon：纯框架（回调骨架 + 模块调度 + 存储原语），不链接规则引擎源，
# 规则能力来自 dlopen 的热插拔模块（basic_rules.so 等）；common.c 为公共工具（日志/路径）。
executable('fuse_daemon',
  fuse_daemon_sources + ['src/core/common.c'],
  include_directories: all_inc_dirs,
  dependencies: project_deps,
  c_args: ['-DFUSE_USE_VERSION=317'],
  link_args: ['-Wl,--export-dynamic'],  # 导出公共符号，供 dlopen 的热插拔模块解析
  install: true,
  install_dir: install_bin_dir
)

if target_os == 'android'
  executable('injector',
    injector_sources + common_sources,
    include_directories: all_inc_dirs,
    dependencies: project_deps,
    install: true,
    install_dir: install_bin_dir
  )
endif

executable('log_monitor',
  ['src/log/log_monitor.c'] + common_sources,
  include_directories: all_inc_dirs,
  dependencies: project_deps,
  install: true,
  install_dir: install_bin_dir
)

executable('log_ctl',
  ['src/log/log_ctl.c'] + common_sources,
  include_directories: all_inc_dirs,
  dependencies: project_deps,
  install: true,
  install_dir: install_bin_dir
)

# ================= 热插拔模块 =================
# basic_rules：基础规则模块（REDIRECT/SANDBOX/HIDE/ALLOW/RO），
# 由 fuse_daemon 启动后 dlopen 热加载。决策引擎自包含，
# 日志等公共符号经主程序导出表解析（fuse_daemon 需 -Wl,--export-dynamic）。
basic_rules_sources = [
    'src/modules/basic_rules/basic_rules.c',
    'src/modules/basic_rules/br_rules.c',
    'src/config/config_parser.c',
    'src/config/path_vars.c',
    'src/core/path_trie.c',
    'src/core/uid_map.c',
    'src/core/fast_pid.c',
]

shared_library('basic_rules',
  basic_rules_sources,
  include_directories: all_inc_dirs,
  dependencies: [dependency('threads')],
  name_prefix: '',  # 生成 basic_rules.so（加载器按 <模块名>.so 扫描，与目录名一致）
  install: true,
  install_dir: install_bin_dir + '/modules/basic_rules'
)

# ftp_module：FTP 存储后端模块（BACKEND 类型，dlopen 共享库）。
# 由 fuse_daemon 启动后热加载（与 basic_rules 同构）：解析 ftp.conf 并把
# FTP 服务器挂载为本地 FUSE 文件系统，经 get_vars 注册 FTP_<段名> 变量。
ftp_module_sources = [
    'src/modules/ftp/ftp_module.c',
    'src/modules/ftp/ftp_conf.c',
    'src/modules/ftp/ftp_client.c',
    'src/modules/ftp/ftp_fuse.c',
    'src/core/common.c',
]

# ftp_module：FTP 存储后端模块（BACKEND 类型，dlopen 共享库，无 FUSE 实现）。
# 只提供 FTP 操作方法（backend_*），由 fuse_daemon 框架在路径命中时调用；
# 不依赖 libfuse（Android 静态库带 GNU 符号版本无法链接共享库，且框架已
# 实现 FUSE，模块无需重复）。fuse 无关头文件仅 libc。
ftp_module_sources = [
    'src/modules/ftp/ftp_module.c',
    'src/modules/ftp/ftp_conf.c',
    'src/modules/ftp/ftp_client.c',
    'src/modules/ftp/ftp_backend.c',
    'src/core/common.c',
]

shared_library('ftp_module',
  ftp_module_sources,
  include_directories: all_inc_dirs,
  dependencies: [dependency('threads')],
  name_prefix: '',  # 生成 ftp_module.so（加载器按 <模块名>.so 扫描，与目录名一致）
  install: true,
  install_dir: install_bin_dir + '/modules/ftp_module'
)

# ================= 测试 =================
# 测试流程由 Python 脚本完成（tests/ 目录），详见 tests/README.md
message('========================================')
message('构建配置信息:')
message('  目标平台: ' + target_os)
message('  CPU/系统: ' + target_triplet)
message('  Debug 模式: ' + (enable_debug ? '启用' : '禁用'))
message('========================================')
