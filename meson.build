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
  fuse3_dep = dependency('fuse3', version: '>=3.6', required: true)
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
    opt_flags = ['-O0', '-g3', '-ggdb3', '-fno-omit-frame-pointer', '-fstack-protector-all', '-DDEBUG=1', '-DNSP_ENABLE_IO_LOG'] + disable_warnings
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
else
  # 全局替换式挂载方案测试驱动（仅 GNU 构建）：injector 本体仅 Android 交叉构建，
  # GNU 测试无法直接运行它；本驱动链接 ns_utils 的全局替换原语并以 CLI 暴露，
  # 供 tests/test_global_replace.py 在私有挂载命名空间中模拟安卓视图验证。
  executable('global_replace_ctl',
    ['src/injector/global_replace_ctl.c', 'src/injector/ns_utils.c',
     'src/injector/inject_target.c', 'src/injector/mount_manager.c',
     'src/core/fast_pid.c'] + common_sources,
    include_directories: all_inc_dirs,
    dependencies: project_deps,
    install: false
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

# rule_server：规则控制守护进程（前端经 nsp_rule_socket 抽象 UDS 以 JSON 行协议
# 动态增删/启停规则、重载配置、停止注入）。纯文件级操作，仅依赖 json-c，
# 不链接 libfuse3；Android/GNU 均构建（路径经 CONFIG_DIR 宏适配）。
executable('rule_server',
  ['src/rule/rule_server.c'],
  include_directories: all_inc_dirs,
  dependencies: json_c,
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
  c_args: ['-DNSP_MODULE_BUILD'],  # 模块独立 ABI：仅模块激活 nsp_module.h 运行时段
  name_prefix: '',  # 生成 basic_rules.so（加载器按 <模块名>.so 扫描，与目录名一致）
  install: true,
  install_dir: install_bin_dir + '/modules/basic_rules'
)

# 模块规则类型注册文件：rule_server 扫描合并动态规则类型（格式见 nsp_module.h）
install_data('src/modules/basic_rules/basic_rules.rules',
  install_dir: install_bin_dir + '/modules/basic_rules'
)

# ftp_module：FTP 存储后端模块（BACKEND 类型，dlopen 共享库，无 FUSE 实现）。
# 使用 libcurl（8.21.0+）处理所有 FTP 协议操作，模块仅负责转发。
ftp_module_sources = [
    'src/modules/ftp/ftp_module.c',
    'src/modules/ftp/ftp_conf.c',
    'src/modules/ftp/ftp_backend_libcurl.c',
]

if target_os == 'gnu'
  ftp_curl_dep = dependency('libcurl', version: '>=8.21.0', required: false)
  if not ftp_curl_dep.found()
    cc = meson.get_compiler('c')
    ftp_curl_dep = cc.find_library('curl', required: true)
    # find_library 不校验版本：运行时检查 curl_version_info >= 8.21.0，
    # 防止系统旧 curl 绕过主查找的版本门槛（编译失败或行为不符）
    curl_ver_check = cc.run('''
      #include <curl/curl.h>
      #include <stdio.h>
      int main(void) {
        curl_version_info_data *v = curl_version_info(CURLVERSION_NOW);
        int maj = 0, min = 0, pat = 0;
        if (sscanf(v->version, "%d.%d.%d", &maj, &min, &pat) != 3) return 1;
        if (maj > 8 || (maj == 8 && (min > 21 || (min == 21 && pat >= 0)))) return 0;
        fprintf(stderr, "libcurl %s 过旧，需要 >= 8.21.0\\n", v->version);
        return 1;
      }
    ''', dependencies: ftp_curl_dep)
    if not curl_ver_check.compiled() or curl_ver_check.returncode() != 0
      error('系统 libcurl 版本过旧，需要 >= 8.21.0（fallback find_library 未通过版本校验）')
    endif
  endif
  ftp_curl_inc = []
else
  curl_root = get_option('curl_dir')
  if curl_root == ''
    error('Android 构建需要预构建 libcurl，请用 -Dcurl_dir=<根目录> 指定（含 lib/.libs/libcurl.a 与 include/）')
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
endif

shared_library('ftp_module',
  ftp_module_sources,
  include_directories: [all_inc_dirs, ftp_curl_inc],
  dependencies: [dependency('threads'), ftp_curl_dep],
  c_args: ['-DNSP_MODULE_BUILD'],  # 模块独立 ABI：仅模块激活 nsp_module.h 运行时段
  name_prefix: '',
  install: true,
  install_dir: install_bin_dir + '/modules/ftp_module'
)

# 模块规则类型注册文件：rule_server 扫描合并动态规则类型（格式见 nsp_module.h）
install_data('src/modules/ftp/ftp_module.rules',
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
