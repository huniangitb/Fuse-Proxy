#ifndef FTP_MUX_H
#define FTP_MUX_H
/*
 * ftp_mux.h — FTP 控制面「epoll + curl_multi」连接复用器
 *
 * 背景：控制面（getattr/readdir/DELE/MKD/RMD/RNFR/STOR 空文件……）此前共用
 * 一个 easy 句柄并以 op_lock 串行化（curl easy 句柄非线程安全）。代价有两重：
 *   1. 任何两个控制操作都排队——多个 FUSE 线程同时 stat 一批路径时，
 *      总耗时 = 操作数 × 单次往返；
 *   2. 失败即 `curl_easy_cleanup` 重建句柄——**业务失败**（550 不存在）也会
 *      把健康的控制连接丢掉，下一次操作白付一次 TCP + USER/PASS 登录往返。
 *
 * 本单元把控制面换成 curl_multi + epoll：一个事件线程驱动一个 CURLM 句柄，
 * 提交者在别的线程构造 easy 任务并等结果。
 *   - **连接复用**：CURLM 句柄自带连接缓存（FTP 控制连接保持 + 免重复登录），
 *     传输完成即归还缓存，后续任意任务直接取用；
 *   - **并发**：多任务同时在飞（连接数由 CURLMOPT_MAX_HOST_CONNECTIONS 上限
 *     约束），控制操作不再互相串行；
 *   - **epoll**：socket 回调把 libcurl 的 fd 注册进 epoll，事件线程只在实际
 *     可读/可写/超时时被唤醒，空转零 CPU。
 *
 * 线程模型（libcurl 多接口非线程安全，必须严格单线程持有 CURLM）：
 *   提交者            事件线程（ftp_mux 固定一个）
 *   ftp_mux_perform → 入队 + 唤醒 ──→ 取队 → curl_multi_add_handle
 *     等待完成                     → curl_multi_socket_action + epoll_wait
 *     ← 完成广播 ────────────────  ← curl_multi_info_read → remove_handle
 * 提交者**绝不**触碰 CURLM/easy 在飞状态；easy 交给 mux 后直到 perform
 * 返回前不得再被访问（返回后由调用方 cleanup）。
 */

#include <curl/curl.h>
#include "ftp_conf.h"

typedef struct FtpMux FtpMux;

/* 创建：起 epoll 事件线程 + CURLM 句柄（连接参数不在 mux 上——easy 句柄由
   调用方经 ftp_easy_new 按段配置新建后交给 perform）。失败返回 NULL（无
   epoll/线程资源）。 */
FtpMux* ftp_mux_new(void);

/* 关闭：置停止位、唤醒并 join 事件线程；排队/在途任务以
   CURLE_ABORTED_BY_CALLBACK 归位（调用者不会永久阻塞），并等待所有在途
   提交者退出后才返回。幂等。此后本 mux 只等引用计数归零释放，mux 上的
   perform 立即返回 CURLE_ABORTED_BY_CALLBACK。 */
void ftp_mux_shutdown(FtpMux* m);

/* 引用计数：在途 perform 持有引用，保证 shutdown 后结构体不提前释放 */
FtpMux* ftp_mux_ref(FtpMux* m);
void ftp_mux_unref(FtpMux* m);

/* 同步执行一个任务：把 easy 交给事件线程驱动，阻塞至完成并返回 curl 结果码。
   easy 由调用方创建（ftp_easy_new）并独占；返回后调用方负责 cleanup。
   mux 已 shutdown（或参数为空）时立即返回 CURLE_ABORTED_BY_CALLBACK。 */
CURLcode ftp_mux_perform(FtpMux* m, CURL* easy);

/* 标记缓存的连接可能已损坏：下次 perform 以全新连接（重新登录）执行。
   等价于旧实现 reset_curl 的「重建句柄」语义，但不再影响在途任务，
   也不再因业务失败（550）白白丢掉健康连接。 */
void ftp_mux_invalidate(FtpMux* m);

/* 创建带持久选项的 easy 句柄（FTP 账号 / 弱网超时判定 / PASV 纠偏 / 不跟随
   跳转）。控制面每次操作新建，数据面（读句柄池、写句柄）复用它——这是 FTP
   连接参数的唯一出处。失败返回 NULL。 */
CURL* ftp_easy_new(const FtpServerCfg* cfg);

#endif /* FTP_MUX_H */
