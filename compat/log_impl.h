/*
 * Copyright 2020-2023 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(anjay, CONFIG_ANJAY_LOG_LEVEL);

#define AVS_LOG__TRACE(Variant, ModuleStr, FormatStr, ...) \
    LOG_DBG("[%s] " FormatStr, ModuleStr, ##__VA_ARGS__)
#define AVS_LOG__DEBUG(Variant, ModuleStr, FormatStr, ...) \
    LOG_DBG("[%s] " FormatStr, ModuleStr, ##__VA_ARGS__)
#define AVS_LOG__INFO(Variant, ModuleStr, FormatStr, ...) \
    LOG_INF("[%s] " FormatStr, ModuleStr, ##__VA_ARGS__)
#define AVS_LOG__WARNING(Variant, ModuleStr, FormatStr, ...) \
    LOG_WRN("[%s] " FormatStr, ModuleStr, ##__VA_ARGS__)
#define AVS_LOG__ERROR(Variant, ModuleStr, FormatStr, ...) \
    LOG_ERR("[%s] " FormatStr, ModuleStr, ##__VA_ARGS__)

#define AVS_LOG__LAZY_TRACE AVS_LOG__TRACE
#define AVS_LOG__LAZY_DEBUG AVS_LOG__DEBUG
#define AVS_LOG__LAZY_INFO AVS_LOG__INFO
#define AVS_LOG__LAZY_WARNING AVS_LOG__WARNING
#define AVS_LOG__LAZY_ERROR AVS_LOG__ERROR

#ifndef AVS_LOG_WITH_TRACE
#    undef AVS_LOG__TRACE
#    define AVS_LOG__TRACE(...) ((void) (0))
#endif // AVS_LOG_WITH_TRACE
