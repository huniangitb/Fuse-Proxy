# Zygisk 应用创建通知模块（仅 Android，双 ABI）
#
# 不走 project() 的 C++ 语言支持——那会要求 GNU 构建也具备 C++ 编译器。
# 本模块与主项目零链接关系（独立 dlopen 进 zygote 子进程），故直接以
# custom_target 调 NDK clang++ 编译，主构建体系不受影响。
#
# 必须双 ABI：injector 收到首次 IPC 通知即停止周期扫描（被动模式），只装
# 64 位时 32 位 zygote 上的应用将既无通知也无扫描，彻底漏注入。

# API 级别与顶层 target_triplet（aarch64-linux-android35）同源
zygisk_api = '35'

# 承自上游 CMakeLists 的严苛标志：ANDROID_STL=none 对应 -nostdlib++，
# 禁 RTTI/异常/线程安全静态量，段级回收 + 隐藏符号，产物约 5–7KB。
# -std=c++20：源码使用 designated initializer（C++17 下为扩展）。
zygisk_flags = [
  '-std=c++20', '-shared', '-fPIC', '-Os', '-flto',
  '-nostdlib++', '-fno-exceptions', '-fno-rtti',
  '-fno-use-cxa-atexit', '-fno-threadsafe-statics',
  '-fno-stack-protector',
  '-fvisibility=hidden', '-fvisibility-inlines-hidden',
  '-fdata-sections', '-ffunction-sections',
  '-Wall', '-Wextra',
  '-Wl,--gc-sections', '-Wl,--as-needed', '-Wl,--exclude-libs,ALL', '-Wl,-s',
]

# [Zygisk ABI 目录名, NDK 工具链前缀]
zygisk_abis = [
  ['arm64-v8a',   'aarch64-linux-android'],
  ['armeabi-v7a', 'armv7a-linux-androideabi'],
]

foreach abi : zygisk_abis
  # 编译器经 PATH 解析，与 cross file 的 c/cpp 条目同机制
  # （scripts/android-build.sh 已把 NDK bin 加入 PATH）
  zygisk_cxx = find_program(abi[1] + zygisk_api + '-clang++', required: true)

  custom_target('zygisk_' + abi[0],
    input: 'zygisk_module.cpp',
    output: abi[0] + '.so',
    command: [
      zygisk_cxx, zygisk_flags,
      '-I' + meson.current_source_dir(),
      '@INPUT@', '-llog', '-o', '@OUTPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: 'zygisk',   # 模块 zip 的 zygisk/ 目录，与 bin/ 平级
  )
endforeach
