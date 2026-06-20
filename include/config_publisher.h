#ifndef CONFIG_PUBLISHER_H
#define CONFIG_PUBLISHER_H

/**
 * 配置广播服务 —— 通过 Unix Domain Socket (SOCK_DGRAM) + epoll
 * 以 JSON 格式实时公布当前加载的配置信息（injector.conf + App-rules 规则，包含已编译的 Trie 树规则）。
 *
 * 使用方式:
 *   - 发送空 datagram 或 "GET"           → 接收方立即收到全量运行时解析后 JSON
 *   - 发送 "STATIC"                      → 接收方收到磁盘上的原始配置文件及内容
 *   - 发送 "SUBSCRIBE"                   → 注册为订阅者，立即推送一次，后续配置变更自动推送
 *   - 发送 "UNSUBSCRIBE"                 → 取消订阅
 *
 * 抽象 Socket 路径: nsp_config_broadcast
 */

#include <sys/types.h>

/**
 * 初始化配置广播 UDS DGRAM 服务并加入全局 epoll
 * 成功返回 socket fd，失败返回 -1
 */
int config_publisher_init(void);

/**
 * 清理配置广播资源，从 epoll 移除并关闭 socket
 */
void config_publisher_cleanup(int fd);

/**
 * 处理收到的 datagram 请求（epoll 可读回调）
 * 根据命令执行 GET / STATIC / SUBSCRIBE / UNSUBSCRIBE 并回传相应的 JSON
 */
void config_publisher_handle_readable(int fd);

/**
 * 广播当前全量配置 JSON 给所有已注册并处于活跃状态的订阅者
 * 在规则重载（SIGHUP 或 inotify 触发 reload_config_rules_diff）完成后被调用
 */
void config_publisher_broadcast(void);

#endif /* CONFIG_PUBLISHER_H */