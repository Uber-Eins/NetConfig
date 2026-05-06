/**
 *
 * IPPure IP 纯净度检测(适配 Sub-Store Node.js 版)
 *
 * 数据源: https://ippure.com/MyIP-Info-API.html
 *
 * HTTP META(https://github.com/xream/http-meta) 参数
 * - [http_meta_protocol] 协议 默认: http
 * - [http_meta_host] 服务地址 默认: 127.0.0.1
 * - [http_meta_port] 端口号 默认: 9876
 * - [http_meta_authorization] Authorization 默认无
 * - [http_meta_start_delay] 初始启动延时(单位: 毫秒) 默认: 3000
 * - [http_meta_proxy_timeout] 每个节点耗时(单位: 毫秒). 默认: 10000
 *
 * 其它参数
 * - [method] 请求方法. 默认 get
 * - [api] IPPure API. 默认 https://my.ippure.com/v1/info
 * - [retries] 重试次数 默认 1
 * - [retry_delay] 重试延时(单位: 毫秒) 默认 1000
 * - [concurrency] 并发数 默认 10
 * - [timeout] 请求超时(单位: 毫秒) 默认 5000
 * - [ippure] 在节点上附加 _ippure 字段, 默认不附加
 * - [incompatible] 在节点上附加 _incompatible 字段来标记当前客户端不兼容该协议, 默认不附加
 * - [remove_incompatible] 移除当前客户端不兼容的协议. 默认不移除.
 * - [remove_failed] 移除检测失败的节点. 默认不移除.
 * - [cache] 使用缓存. 默认不使用缓存
 * - [disable_failed_cache/ignore_failed_error] 禁用失败缓存. 即不缓存失败结果
 *
 * 插入格式: [fraudScore|住宅/机房|原生/广播] 节点名
 * - isResidential 为 true 时显示住宅, 否则显示机房
 * - isBroadcast 为 true 时显示原生, 否则显示广播
 */

async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore
    const cacheEnabled = $arguments.cache
    const cache = scriptResourceCache
    const disableFailedCache = $arguments.disable_failed_cache || $arguments.ignore_failed_error
    const remove_failed = $arguments.remove_failed
    const remove_incompatible = $arguments.remove_incompatible
    const incompatibleEnabled = $arguments.incompatible
    const ippureEnabled = $arguments.ippure
    const http_meta_host = $arguments.http_meta_host ?? '127.0.0.1'
    const http_meta_port = $arguments.http_meta_port ?? 9876
    const http_meta_protocol = $arguments.http_meta_protocol ?? 'http'
    const http_meta_authorization = $arguments.http_meta_authorization ?? ''
    const http_meta_api = `${http_meta_protocol}://${http_meta_host}:${http_meta_port}`
    const http_meta_start_delay = parseFloat($arguments.http_meta_start_delay ?? 3000)
    const http_meta_proxy_timeout = parseFloat($arguments.http_meta_proxy_timeout ?? 10000)
    const method = $arguments.method || 'get'
    const url = $arguments.api || 'https://my.ippure.com/v1/info'

    const internalProxies = []
    proxies.map((proxy, index) => {
        try {
            const node = ProxyUtils.produce([{ ...proxy }], 'ClashMeta', 'internal')?.[0]
            if (node) {
                for (const key in proxy) {
                    if (/^_/i.test(key)) {
                        node[key] = proxy[key]
                    }
                }
                internalProxies.push({ ...node, _proxies_index: index })
            } else {
                proxies[index]._incompatible = true
            }
        } catch (e) {
            proxies[index]._incompatible = true
            $.error(e)
        }
    })

    $.info(`核心支持节点数: ${internalProxies.length}/${proxies.length}`)
    if (!internalProxies.length) return finalizeProxies(proxies)

    if (cacheEnabled) {
        try {
            let allCached = true
            for (var i = 0; i < internalProxies.length; i++) {
                const proxy = internalProxies[i]
                const id = getCacheId({ proxy, url })
                const cached = cache.get(id)
                if (cached) {
                    if (cached.api) {
                        applyIPPureResult(proxy, cached.api)
                    } else {
                        if (disableFailedCache) {
                            allCached = false
                            break
                        }
                    }
                } else {
                    allCached = false
                    break
                }
            }
            if (allCached) {
                $.info('所有节点都有有效缓存 完成')
                return finalizeProxies(proxies)
            }
        } catch (e) { }
    }

    const http_meta_timeout = http_meta_start_delay + internalProxies.length * http_meta_proxy_timeout

    let http_meta_pid
    let http_meta_ports = []

    try {
        const res = await http({
            retries: 0,
            method: 'post',
            url: `${http_meta_api}/start`,
            headers: {
                'Content-type': 'application/json',
                Authorization: http_meta_authorization,
            },
            body: JSON.stringify({
                proxies: internalProxies,
                timeout: http_meta_timeout,
            }),
        })
        let body = res.body
        try {
            body = JSON.parse(body)
        } catch (e) { }

        const { ports, pid } = body
        if (!pid || !ports) {
            throw new Error(`======== HTTP META 启动失败 ====\n${body}`)
        }
        http_meta_pid = pid
        http_meta_ports = ports
        $.info(
            `\n======== HTTP META 启动 ====\n[端口] ${ports}\n[PID] ${pid}\n[超时] 若未手动关闭 ${Math.round(http_meta_timeout / 60 / 10) / 100
            } 分钟后自动关闭\n`
        )
        $.info(`等待 ${http_meta_start_delay / 1000} 秒后开始检测`)
        await $.wait(http_meta_start_delay)

        const concurrency = Math.max(1, parseInt($arguments.concurrency || 10) || 10)
        await executeAsyncTasks(
            internalProxies.map(proxy => () => check(proxy)),
            { concurrency }
        )
    } finally {
        if (http_meta_pid) {
            try {
                const res = await http({
                    method: 'post',
                    url: `${http_meta_api}/stop`,
                    headers: {
                        'Content-type': 'application/json',
                        Authorization: http_meta_authorization,
                    },
                    body: JSON.stringify({
                        pid: [http_meta_pid],
                    }),
                })
                $.info(`\n======== HTTP META 关闭 ====\n${JSON.stringify(res, null, 2)}`)
            } catch (e) {
                $.error(e)
            }
        }
    }

    return finalizeProxies(proxies)

    async function check(proxy) {
        const id = cacheEnabled ? getCacheId({ proxy, url }) : undefined
        try {
            if (cacheEnabled) {
                const cached = cache.get(id)
                if (cached) {
                    if (cached.api) {
                        $.info(`[${proxy.name}] 使用成功缓存`)
                        applyIPPureResult(proxy, cached.api)
                        return
                    } else {
                        if (disableFailedCache) {
                            $.info(`[${proxy.name}] 不使用失败缓存`)
                        } else {
                            $.info(`[${proxy.name}] 使用失败缓存`)
                            return
                        }
                    }
                }
            }

            const index = internalProxies.indexOf(proxy)
            const startedAt = Date.now()
            const res = await http({
                proxy: `http://${http_meta_host}:${http_meta_ports[index]}`,
                method,
                headers: {
                    'User-Agent':
                        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1',
                },
                url,
            })

            const status = parseInt(res.status || res.statusCode || 200)
            const latency = `${Date.now() - startedAt}`
            let api = String(lodash_get(res, 'body') ?? '')
            try {
                api = JSON.parse(api)
            } catch (e) { }

            if (status == 200 && isValidIPPureResult(api)) {
                applyIPPureResult(proxy, api)
                $.info(`[${proxy.name}] status: ${status}, latency: ${latency}, ippure: ${buildIPPureTag(api)}`)
                $.log(`[${proxy.name}] api: ${JSON.stringify(api, null, 2)}`)
                if (cacheEnabled) {
                    $.info(`[${proxy.name}] 设置成功缓存`)
                    cache.set(id, { api })
                }
            } else {
                $.info(`[${proxy.name}] status: ${status}, latency: ${latency}, api 返回异常`)
                if (cacheEnabled) {
                    $.info(`[${proxy.name}] 设置失败缓存`)
                    cache.set(id, {})
                }
            }
        } catch (e) {
            $.error(`[${proxy.name}] ${e.message ?? e}`)
            if (cacheEnabled) {
                $.info(`[${proxy.name}] 设置失败缓存`)
                cache.set(id, {})
            }
        }
    }

    function applyIPPureResult(proxy, api) {
        const index = proxy._proxies_index
        proxies[index].name = insertIPPureTag(proxies[index].name, api)
        proxies[index]._ippure = api
    }

    function insertIPPureTag(name = '', api = {}) {
        const cleanedName = String(name).replace(/^\[(?:-?\d+(?:\.\d+)?|-)\|(?:住宅|机房)\|(?:原生|广播)\]\s*/g, '')
        return `${buildIPPureTag(api)} ${cleanedName}`
    }

    function buildIPPureTag(api = {}) {
        const score = api.fraudScore ?? '-'
        const residential = toBoolean(api.isResidential) ? '住宅' : '机房'
        const broadcast = toBoolean(api.isBroadcast) ? '原生' : '广播'
        return `[${score}|${residential}|${broadcast}]`
    }

    function isValidIPPureResult(api) {
        return api && typeof api === 'object' && Object.prototype.hasOwnProperty.call(api, 'fraudScore')
    }

    function toBoolean(value) {
        return value === true || String(value).toLowerCase() === 'true'
    }

    function finalizeProxies(list) {
        if (remove_incompatible || remove_failed) {
            list = list.filter(p => {
                if (remove_incompatible && p._incompatible) {
                    return false
                } else if (remove_failed && !p._ippure) {
                    return !remove_incompatible && p._incompatible
                }
                return true
            })
        }

        if (!ippureEnabled || !incompatibleEnabled) {
            list = list.map(p => {
                if (!ippureEnabled) {
                    delete p._ippure
                }
                if (!incompatibleEnabled) {
                    delete p._incompatible
                }
                return p
            })
        }
        return list
    }

    async function http(opt = {}) {
        const METHOD = opt.method || $arguments.method || 'get'
        const TIMEOUT = parseFloat(opt.timeout || $arguments.timeout || 5000)
        const RETRIES = parseFloat(opt.retries ?? $arguments.retries ?? 1)
        const RETRY_DELAY = parseFloat(opt.retry_delay ?? $arguments.retry_delay ?? 1000)

        let count = 0
        const fn = async () => {
            try {
                return await $.http[METHOD]({ ...opt, timeout: TIMEOUT })
            } catch (e) {
                if (count < RETRIES) {
                    count++
                    const delay = RETRY_DELAY * count
                    await $.wait(delay)
                    return await fn()
                } else {
                    throw e
                }
            }
        }
        return await fn()
    }

    function lodash_get(source, path, defaultValue = undefined) {
        const paths = path.replace(/\[(\d+)\]/g, '.$1').split('.')
        let result = source
        for (const p of paths) {
            result = Object(result)[p]
            if (result === undefined) {
                return defaultValue
            }
        }
        return result
    }

    function getCacheId({ proxy = {}, url }) {
        return `http-meta:ippure:${url}:${JSON.stringify(
            Object.fromEntries(Object.entries(proxy).filter(([key]) => !/^(name|collectionName|subName|id|_.*)$/i.test(key)))
        )}`
    }

    function executeAsyncTasks(tasks, { wrap, result, concurrency = 1 } = {}) {
        return new Promise(async (resolve, reject) => {
            try {
                let running = 0
                const results = []

                let index = 0

                function executeNextTask() {
                    while (index < tasks.length && running < concurrency) {
                        const taskIndex = index++
                        const currentTask = tasks[taskIndex]
                        running++

                        currentTask()
                            .then(data => {
                                if (result) {
                                    results[taskIndex] = wrap ? { data } : data
                                }
                            })
                            .catch(error => {
                                if (result) {
                                    results[taskIndex] = wrap ? { error } : error
                                }
                            })
                            .finally(() => {
                                running--
                                executeNextTask()
                            })
                    }

                    if (running === 0) {
                        return resolve(result ? results : undefined)
                    }
                }

                await executeNextTask()
            } catch (e) {
                reject(e)
            }
        })
    }
}
