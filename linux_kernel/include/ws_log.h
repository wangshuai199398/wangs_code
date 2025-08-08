#ifndef __WS_LOG_H_
#define __WS_LOG_H_

#include "../ws_log.h"

#define ws_err(f, arg...) pr_err("%s: " f, WS_HW_NAME, ##arg)

#endif
