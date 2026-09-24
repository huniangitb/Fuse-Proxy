#ifndef NSP_CFG_VIEW_H
#define NSP_CFG_VIEW_H
/*
 * nsp_cfg_view.h — 配置扁平视图（框架 → 模块下发的规则/变量载体）
 *
 * 定位：框架完成配置的**读取**（文件 I/O + 行级词法 + 段头识别）后，把结果
 * 以本头的扁平记录形式下发给模块；模块据此重建自己的索引，**不触碰文件系统、
 * 不跑 inotify**。框架按模块经 subscribe_rules 申请的规则类型过滤，实现模块间
 * 规则隔离（A 模块看不到 B 模块的规则）。
 *
 * 分层：本头同时被 config_parser.h（框架侧构建视图）与 nsp_module.h（模块侧
 * 消费视图）包含，是两者的共享契约；作为模块 ABI 的一部分随 SDK 一并分发。
 *
 * 视图只读：记录中的字符串归框架所有，仅在本次下发（或下一次重载）前有效；
 * 消费者不得修改，也不得在回调返回后继续持有。
 */
#include <stdint.h>

/* 记录种类。顺序即语义顺序：主文件记录在前，App-rules 记录在后。 */
typedef enum {
    NSP_CFG_REC_SECTION = 0,  /* 段头：[名称] 可选 ON/OFF；text=段名（不含方括号与 :uid） */
    NSP_CFG_REC_RULE,         /* 规则行：text=已去注释/首尾空白的行文本，type=首 token */
    NSP_CFG_REC_APP_FILE,     /* 进入 App-rules 文件：text=包名，uid=归属用户 */
    NSP_CFG_REC_APP_DISABLED, /* 停用标记（<pkg>.conf.disabled 且无 .conf）：text=包名 */
} NspCfgRecKind;

typedef struct {
    uint8_t kind;     /* NspCfgRecKind */
    uint8_t enabled;  /* SECTION：段头 ON/OFF（其余记录未用） */
    int32_t uid;      /* SECTION：段头 :uid（-1=未指定）；APP_*：归属 user id */
    int32_t line_no;  /* 源文件行号（诊断） */
    const char* file; /* 源文件路径（诊断，可 NULL） */
    const char* type; /* RULE：首 token（规则类型名；NAME=VALUE 变量行归一为 "VAR"） */
    const char* text; /* 含义随 kind 见上；存储归框架所有 */
} NspCfgRec;

/* 下发给单个模块的配置视图（已按该模块的订阅过滤） */
typedef struct {
    uint32_t version;    /* 视图协议版本（= NSP_CFG_VIEW_VERSION） */
    uint64_t generation; /* 配置代际：重载后递增，模块据此跳过无变化重建 */
    const NspCfgRec* recs;
    int count;
} NspModuleConfig;

#define NSP_CFG_VIEW_VERSION 1u

#endif /* NSP_CFG_VIEW_H */
