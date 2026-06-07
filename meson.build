project('ultimate_fuse_system', 'c',
  version: '1.0.0',
  default_options: [
    'c_std=c23', 
    'warning_level=3', 
    'strip=true'
  ]
)

cc = meson.get_compiler('c')

# 选项配置
enable_debug = get_option('enable_debug')
with_asan = get_option('with_asan')
with_ubsan = get_option('with_ubsan')

# ================= 编译目标配置 =================
target_triplet = 'aarch64-linux-android35'
if not meson.is_cross_build()
  add_project_arguments('--target=' + target_triplet, language: 'c')
  add_project_link_arguments('--target=' + target_triplet, language: 'c')
endif

is_clang = cc.get_id() == 'clang'

# ================= 依赖查找 =================
fuse3_root = '/data/user/0/com.termux/files/home/fuse3-static-install4'
fuse_inc = include_directories(fuse3_root + '/include')
fuse_lib = cc.find_library('fuse3', dirs: [fuse3_root + '/lib'], static: true, required: true)

# 自动探测 libiconv
libiconv = cc.find_library('iconv', required: true)

# 项目通用依赖
project_deps = [
  dependency('threads'),
  fuse_lib,
  libiconv
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
    # 针对 AArch64 的高性能优化标志
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

# ================= 源码集合 =================
common_sources = [
    'src/core/common.c',
    'src/config/config_parser.c',
    'src/core/fast_search.c'
]

fuse_daemon_sources = ['src/daemon/fuse_daemon.c', 'src/daemon/vfs_core.c', 'src/core/crash_dump.c']
injector_sources = ['src/injector/injector.c', 'src/injector/inject_target.c', 'src/injector/mount_manager.c', 'src/injector/ipc_server.c', 'src/injector/ns_utils.c', 'src/core/fast_pid.c']

# ================= 构建可执行文件 =================
install_bin_dir = 'bin'

executable('fuse_daemon',
  fuse_daemon_sources + common_sources,
  include_directories: [fuse_inc, inc_dir],
  dependencies: project_deps,
  c_args: ['-DFUSE_USE_VERSION=317'],
  install: true,
  install_dir: install_bin_dir
)

executable('injector',
  injector_sources + common_sources,
  include_directories: inc_dir,
  dependencies: project_deps,
  install: true,
  install_dir: install_bin_dir
)

executable('log_monitor',
  ['src/log/log_monitor.c'] + common_sources,
  include_directories: inc_dir,
  dependencies: project_deps,
  install: true,
  install_dir: install_bin_dir
)

executable('log_ctl',
  ['src/log/log_ctl.c'] + common_sources,
  include_directories: inc_dir,
  dependencies: project_deps,
  install: true,
  install_dir: install_bin_dir
)

message('========================================')
message('构建配置信息:')
message('  平台: ' + target_triplet)
message('  Debug 模式: ' + (enable_debug ? '启用' : '禁用'))
message('========================================')