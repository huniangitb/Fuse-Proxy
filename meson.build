project('ultimate_fuse_system', 'c',
  version: '1.0.0',
  default_options: ['c_std=c11', 'warning_level=3', 'strip=true'])

cc = meson.get_compiler('c')

# 选项配置
enable_debug = get_option('enable_debug')
with_asan = get_option('with_asan')
with_ubsan = get_option('with_ubsan')

# 设置 Android 目标平台
target_triplet = 'aarch64-linux-android35'
add_global_arguments(f'--target=@target_triplet@', language: 'c')
add_global_link_arguments(f'--target=@target_triplet@', language: 'c')

is_clang = cc.get_id() == 'clang'

# FUSE 库配置
fuse3_root = '/data/user/0/com.termux/files/home/fuse3-static-install4'
fuse_inc = include_directories(fuse3_root + '/include')
fuse_lib = cc.find_library('fuse3', dirs: [fuse3_root + '/lib'], static: true, required: true)

# ========== 关键修改：添加 libiconv 依赖 ==========
# 查找 libiconv（Termux 中库名为 iconv，文件为 libiconv.a 或 libiconv.so）
libiconv = cc.find_library('iconv', required: true, dirs: ['/data/data/com.termux/files/usr/lib'])
# ================================================

fuse_dep = declare_dependency(
    include_directories: fuse_inc, 
    dependencies: [fuse_lib]  # 添加 libiconv 依赖
)

# 系统依赖
thread_dep = dependency('threads') 
system_libs = [
    cc.find_library('pthread'),
    cc.find_library('rt'),
    cc.find_library('dl'),
    cc.find_library('m')
]

# 编译标志设置
if enable_debug
    opt_flags = ['-O0', '-g3', '-ggdb3', '-gdwarf-4', '-fno-omit-frame-pointer', '-fstack-protector-all']
    opt_flags += ['-DDEBUG=1', '-D_DEBUG', '-Wall', '-Wextra', '-Werror=implicit-function-declaration', '-Wno-gnu-zero-variadic-macro-arguments']
    link_flags = (with_asan ? ['-fsanitize=address'] : []) + (with_ubsan ? ['-fsanitize=undefined'] : [])
else
    o3_flag = ['-O3']
    lto_flags = ['-flto']
    native_flags = ['-march=native', '-mtune=native']
    disable_warnings = ['-Wno-gnu-zero-variadic-macro-arguments']
    pbqp_flags = is_clang ? ['-mllvm', '-regalloc=pbqp'] : []
    llvm_extra_flags = is_clang ? ['-mllvm', '--enable-global-merge', '-mllvm', '--strip-global-constants', '-mllvm', '-unroll-threshold=64'] : []
    
    opt_flags = o3_flag + lto_flags + native_flags + pbqp_flags + llvm_extra_flags + disable_warnings
    link_flags = ['-Wl,-s', '-Wl,--gc-sections']
endif

c_args_all = opt_flags
link_args_all = link_flags

# 模块化源码集合
common_sources = ['common.c', 'config_parser.c']

fuse_daemon_sources = [
    'fuse_daemon.c',
    'vfs_core.c',
    'crash_dump.c'
]

injector_sources = [
    'injector.c',
    'inject_target.c',
    'mount_manager.c',
    'ipc_server.c',
    'ns_utils.c',
    'fast_pid.c'
]

install_bin_dir = 'bin'

# 构建可执行文件
fuse_daemon_exe = executable('fuse_daemon',
  fuse_daemon_sources + common_sources,
  dependencies: [fuse_dep, thread_dep] + system_libs,  # fuse_dep 已包含 libiconv
  c_args: c_args_all + ['-DFUSE_USE_VERSION=317'],
  link_args: link_args_all,
  install: true,
  install_dir: install_bin_dir
)

injector_exe = executable('injector',
  injector_sources + common_sources,
  dependencies: system_libs + [thread_dep], 
  c_args: c_args_all,
  link_args: link_args_all,
  install: true,
  install_dir: install_bin_dir
)

log_monitor_exe = executable('log_monitor',
  ['log_monitor.c'] + common_sources,
  dependencies: system_libs + [thread_dep],
  c_args: c_args_all,
  link_args: link_args_all,
  install: true,
  install_dir: install_bin_dir
)

log_ctl_exe = executable('log_ctl',
  ['log_ctl.c'] + common_sources,
  dependencies: system_libs,
  c_args: c_args_all,
  link_args: link_args_all,
  install: true,
  install_dir: install_bin_dir
)

# 配置确认
message('========================================')
message('构建配置信息:')
message('  编译器: ' + cc.get_id())
message('  调试模式: ' + (enable_debug ? '启用' : '禁用'))
message('  libiconv: ' + (libiconv.found() ? '已找到' : '未找到'))
message('========================================')