#ifndef FW_INGEST_H
#define FW_INGEST_H
/*
 * fw_ingest.h — 后端落点的本地物化（事件通道打开时才做）
 *
 * 后端的字节留在远端，存储树里那个落点下没有任何本地文件；而媒体扫描侧的每一跳
 * 都按本地路径工作——QUERY 的 exists 探测对真实落点 lstat，MediaStore 的
 * scan_file 也只会打开本地文件。于是"上传完成"对扫描侧完全不可见，只发一条刷新
 * 请求只会扫到空。本模块在写收尾成功后把后端内容回读一遍，落在该路径的真实
 * 落点上（与事件里的 rpath 同一个答案：都经 fw_rules_resolve 决策单点解析），
 * 让后续那一跳有东西可扫。
 *
 * 三条边界：
 *   1. 只物化媒体扩展名（判定走 fw_media_kind_of）：入库是唯一用途，其它类型
 *      复制一份只是占位。
 *   2. 通道关着（[GLOBAL] FUSE_EVENTS 缺省 OFF）或没有订阅者时什么都不做——
 *      本地副本的唯一消费者就是媒体扫描。
 *   3. 失败只记日志、不回传：close() 不该因为"顺手做的镜像"而失败。半成品与
 *      落点同目录（改名才能原子生效），扩展名不是媒体，不会被当成媒体入库。
 */
#include <sys/types.h>

/* 把 slot 后端上 fuse_path（"/<user>/<sub>"）的内容物化到它的真实落点。uid/pid
   是发起写入的调用方——落点要按它生效的规则解析（沙盒类的重定向会换目录），
   传错了就会把副本放到对端扫不到的地方。
   返回 0 或负 errno；调用方按"尽力而为"处理，不要把它传播给 close()。
   不加锁：同一路径的并发物化靠临时名 + 原子改名兜底，最后落地的一份为准。 */
int fw_ingest_materialize(int slot, const char* fuse_path, uid_t uid, pid_t pid);

#endif /* FW_INGEST_H */
