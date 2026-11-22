#include "mount_ops.h"

#include <pthread.h>

/* 静态初始化：无需 init 调用，也不留「初始化失败」这种半状态。锁只在进程内使用，
 * 竞争者固定是三条线程（维护 worker / 审计 worker / 事件循环的 trylock）。 */
static pthread_mutex_t g_mount_ops_mu = PTHREAD_MUTEX_INITIALIZER;

void mount_ops_begin(void) { pthread_mutex_lock(&g_mount_ops_mu); }

void mount_ops_end(void) { pthread_mutex_unlock(&g_mount_ops_mu); }

bool mount_ops_try_begin(void) { return pthread_mutex_trylock(&g_mount_ops_mu) == 0; }