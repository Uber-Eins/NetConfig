/**
 * IPPure + UDP node formatter for Sub-Store Node.js.
 *
 * HTTP META arguments:
 * - [http_meta_protocol] default: http
 * - [http_meta_host] default: 127.0.0.1
 * - [http_meta_port] default: 9876
 * - [http_meta_authorization] default: empty
 * - [http_meta_start_delay] default: 3000
 * - [http_meta_proxy_timeout] default: 10000
 *
 * Check arguments:
 * - [api] default: https://my.ippure.com/v1/info
 * - [method] default: get
 * - [udp] run UDP test, default: true
 * - [ntp] UDP test NTP server, default: time.apple.com
 * - [timeout] request timeout, default: 5000
 * - [udp_timeout] UDP test timeout, default: timeout
 * - [retries] default: 1
 * - [retry_delay] default: 1000
 * - [concurrency] default: 10
 * - [cache] use Sub-Store scriptResourceCache
 * - [disable_failed_cache/ignore_failed_error] do not reuse failed cache
 * - [remove_failed] remove nodes without valid IPPure response
 * - [remove_incompatible] remove nodes that cannot be produced for ClashMeta
 * - [include_unsupported_proxy] pass unsupported proxy types to ClashMeta
 * - [dialer_proxy/front_proxy/upstream_proxy] front proxy URL, e.g. http://127.0.0.1:7890 or socks5://127.0.0.1:7891
 * - [asn_lookup/internal] use MMDB ipaso/geoip lookup, default: true
 * - [mmdb_country_path] MaxMind GeoLite2 Country database path
 * - [mmdb_asn_path] MaxMind GeoLite2 ASN database path
 * - [node_info] keep _node_info field
 * - [incompatible] keep _incompatible field
 *
 * Output:
 * [fraudScore|🏠/🏢|🌱/📡|UDP|xN] flag landing-AS-organization
 * IPv6-only IPPure responses do not include fraudScore; those are formatted as [IPv6|...].
 */

async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore
    const cacheEnabled = toBoolean($arguments.cache)
    const cache = scriptResourceCache
    const disableFailedCache = toBoolean($arguments.disable_failed_cache || $arguments.ignore_failed_error)
    const removeFailed = toBoolean($arguments.remove_failed)
    const removeIncompatible = toBoolean($arguments.remove_incompatible)
    const keepIncompatible = toBoolean($arguments.incompatible)
    const keepNodeInfo = toBoolean($arguments.node_info)
    const includeUnsupportedProxy = toBoolean($arguments.include_unsupported_proxy)
    const udpEnabled = !hasArgument('udp') || toBoolean($arguments.udp)
    const httpMetaHost = $arguments.http_meta_host ?? '127.0.0.1'
    const httpMetaPort = $arguments.http_meta_port ?? 9876
    const httpMetaProtocol = $arguments.http_meta_protocol ?? 'http'
    const httpMetaAuthorization = $arguments.http_meta_authorization ?? ''
    const httpMetaApi = `${httpMetaProtocol}://${httpMetaHost}:${httpMetaPort}`
    const httpMetaStartDelay = parseFloat($arguments.http_meta_start_delay ?? 3000)
    const httpMetaProxyTimeout = parseFloat($arguments.http_meta_proxy_timeout ?? 10000)
    const method = $arguments.method || 'get'
    const url = $arguments.api || 'https://my.ippure.com/v1/info'
    const ntp = $arguments.ntp || 'time.apple.com'
    const frontProxyUrl = $arguments.dialer_proxy || $arguments.front_proxy || $arguments.upstream_proxy
    const frontProxy = parseFrontProxy(frontProxyUrl)
    const asnLookupEnabled = hasArgument('asn_lookup')
        ? toBoolean($arguments.asn_lookup)
        : hasArgument('internal')
            ? toBoolean($arguments.internal)
            : true
    const asnLookup = asnLookupEnabled ? createAsnLookup($, $arguments.mmdb_country_path, $arguments.mmdb_asn_path) : undefined

    const internalProxies = []
    proxies.forEach((proxy, index) => {
        proxy._originalName = proxy._originalName || proxy.name
        proxy._originalServer = proxy._originalServer || proxy.server
        delete proxy._node_info
        delete proxy._ippure
        delete proxy._udp

        try {
            const node = ProxyUtils.produce([{ ...proxy }], 'ClashMeta', 'internal', {
                'include-unsupported-proxy': includeUnsupportedProxy,
            })?.[0]

            if (node) {
                for (const key in proxy) {
                    if (/^_/i.test(key)) {
                        node[key] = proxy[key]
                    }
                }
                internalProxies.push({ ...node, _proxies_index: index })
            } else {
                proxy._incompatible = true
            }
        } catch (e) {
            proxy._incompatible = true
            $.error(e)
        }
    })

    $.info(`核心支持节点数: ${internalProxies.length}/${proxies.length}`)
    if (!internalProxies.length) {
        return finalizeProxies(proxies)
    }

    const pendingProxies = []
    for (const proxy of internalProxies) {
        const id = getCacheId({ proxy, url, udpEnabled, ntp, frontProxyUrl, asnLookupEnabled })
        const cached = cacheEnabled ? cache.get(id) : undefined

        if (cacheEnabled && cached) {
            if (isCacheComplete(cached, udpEnabled)) {
                $.info(`[${proxy.name}] 使用成功缓存`)
                applyCheckResult(proxy, cached)
                continue
            }
            if (cached.failed && !disableFailedCache) {
                $.info(`[${proxy.name}] 使用失败缓存`)
                continue
            }
            $.info(`[${proxy.name}] 不使用失败缓存`)
        }

        pendingProxies.push(proxy)
    }

    if (pendingProxies.length) {
        await runChecks(pendingProxies)
    }

    applyIPv4FallbackForDualStack(proxies)
    proxies.forEach(formatProxyName)
    return finalizeProxies(proxies)

    async function runChecks(checkProxies) {
        const httpMetaTimeout = httpMetaStartDelay + checkProxies.length * httpMetaProxyTimeout
        const frontProxyIndex = checkProxies.length
        const startProxies = checkProxies.map(proxy => {
            const node = { ...proxy }
            if (frontProxy) {
                node['dialer-proxy'] = `proxy-${frontProxyIndex}`
            }
            return node
        })

        if (frontProxy) {
            startProxies.push(frontProxy)
            $.info(`[前置代理] ${frontProxy.type}://${frontProxy.server}:${frontProxy.port}`)
        }

        let httpMetaPid
        let httpMetaPorts = []

        try {
            const res = await http({
                retries: 0,
                method: 'post',
                url: `${httpMetaApi}/start`,
                headers: buildJsonHeaders(),
                body: JSON.stringify({
                    proxies: startProxies,
                    timeout: httpMetaTimeout,
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

            httpMetaPid = pid
            httpMetaPorts = ports
            $.info(
                `\n======== HTTP META 启动 ====\n[端口] ${ports}\n[PID] ${pid}\n[超时] 若未手动关闭 ${
                    Math.round(httpMetaTimeout / 60 / 10) / 100
                } 分钟后自动关闭\n`
            )
            $.info(`等待 ${httpMetaStartDelay / 1000} 秒后开始检测`)
            await $.wait(httpMetaStartDelay)

            const concurrency = Math.max(1, parseInt($arguments.concurrency || 10) || 10)
            await executeAsyncTasks(
                checkProxies.map((proxy, index) => () => check(proxy, httpMetaPorts[index])),
                { concurrency }
            )
        } finally {
            if (httpMetaPid) {
                try {
                    const res = await http({
                        method: 'post',
                        url: `${httpMetaApi}/stop`,
                        headers: buildJsonHeaders(),
                        body: JSON.stringify({
                            pid: [httpMetaPid],
                        }),
                    })
                    $.info(`\n======== HTTP META 关闭 ====\n${JSON.stringify(res, null, 2)}`)
                } catch (e) {
                    $.error(e)
                }
            }
        }
    }

    async function check(proxy, port) {
        const id = cacheEnabled ? getCacheId({ proxy, url, udpEnabled, ntp, frontProxyUrl, asnLookupEnabled }) : undefined
        const startedAt = Date.now()
        let info
        let udp = false

        try {
            info = await checkIPPure(proxy, port)

            if (udpEnabled) {
                udp = await checkUdp(proxy, port)
            }

            if (isValidNodeInfo(info)) {
                const result = { info: enrichNodeInfo(info), udp }
                applyCheckResult(proxy, result)
                $.info(`[${proxy.name}] latency: ${Date.now() - startedAt}, node: ${buildNodeTag(info, udp)}`)
                $.log(`[${proxy.name}] api: ${JSON.stringify(info, null, 2)}`)
                if (cacheEnabled) {
                    $.info(`[${proxy.name}] 设置成功缓存`)
                    cache.set(id, result)
                }
            } else {
                $.info(`[${proxy.name}] latency: ${Date.now() - startedAt}, api 返回异常`)
                if (cacheEnabled) {
                    $.info(`[${proxy.name}] 设置失败缓存`)
                    cache.set(id, { failed: true })
                }
            }
        } catch (e) {
            $.error(`[${proxy.name}] ${e.message ?? e}`)
            if (cacheEnabled) {
                $.info(`[${proxy.name}] 设置失败缓存`)
                cache.set(id, { failed: true })
            }
        }
    }

    async function checkIPPure(proxy, port) {
        const res = await http({
            proxy: `http://${httpMetaHost}:${port}`,
            method,
            headers: {
                'User-Agent':
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1',
            },
            url,
        })

        const status = parseInt(res.status || res.statusCode || 200)
        let info = String(lodashGet(res, 'body') ?? '')
        try {
            info = JSON.parse(info)
        } catch (e) { }

        if (status === 200 && isValidNodeInfo(info)) {
            return info
        }
        return undefined
    }

    function enrichNodeInfo(info = {}) {
        if (!isValidNodeInfo(info) || !asnLookup) {
            return info
        }

        const lookup = asnLookup(info.ip)
        if (!lookup.countryCode && !lookup.aso && !lookup.asn) {
            return info
        }

        return {
            ...info,
            countryCode: lookup.countryCode || info.countryCode,
            asn: lookup.asn || info.asn,
            aso: lookup.aso || info.aso,
        }
    }

    async function checkUdp(proxy, port) {
        try {
            const timeout = parseFloat($arguments.udp_timeout || $arguments.timeout || 5000)
            const res = await http({
                method: 'post',
                timeout: timeout + 1000,
                url: `${httpMetaApi}/udp`,
                headers: buildJsonHeaders(),
                body: JSON.stringify({
                    ntp,
                    port,
                    timeout,
                }),
            })

            let body = String(res.body ?? res.rawBody ?? '')
            try {
                body = JSON.parse(body)
            } catch (e) { }
            return body?.result === 'ok' || body?.data === 'ok'
        } catch (e) {
            $.info(`[${proxy.name}] UDP 检测失败: ${e.message ?? e}`)
            return false
        }
    }

    function applyCheckResult(proxy, result = {}) {
        const index = proxy._proxies_index
        if (result.info) {
            const info = enrichNodeInfo(result.info)
            proxies[index]._node_info = info
            proxies[index]._ippure = info
        }
        proxies[index]._udp = result.udp === true
    }

    function buildJsonHeaders() {
        return {
            'Content-type': 'application/json',
            Authorization: httpMetaAuthorization,
        }
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
                    await $.wait(RETRY_DELAY * count)
                    return await fn()
                }
                throw e
            }
        }
        return await fn()
    }

    function finalizeProxies(list) {
        if (removeIncompatible || removeFailed) {
            list = list.filter(proxy => {
                if (removeIncompatible && proxy._incompatible) {
                    return false
                }
                if (removeFailed && !proxy._node_info) {
                    return !removeIncompatible && proxy._incompatible
                }
                return true
            })
        }

        return list.map(proxy => {
            if (!keepNodeInfo) {
                delete proxy._node_info
                delete proxy._ippure
                delete proxy._udp
            }
            if (!keepIncompatible) {
                delete proxy._incompatible
            }
            return proxy
        })
    }
}

function formatProxyName(proxy = {}) {
    if (!proxy._node_info) {
        return proxy
    }

    const info = proxy._node_info
    const parts = [getPurityLabel(info), pickResidentialIcon(info.isResidential), pickBroadcastIcon(info.isBroadcast)]
    const multiplier = findMultiplier(getOriginalName(proxy)) || (hasOriginalName(proxy) ? '' : findMultiplier(proxy.name))
    const flag = getFlag(info.countryCode || info.country || info.country_code)
    const organization = getOrganization(info)

    if (proxy._udp === true) {
        parts.push('UDP')
    }
    if (multiplier) {
        parts.push(`x${multiplier}`)
    }

    proxy.name = `[${parts.join('|')}] ${[flag, organization || 'Unknown'].filter(Boolean).join(' ')}`
    return proxy
}

function applyIPv4FallbackForDualStack(proxies = []) {
    const ipv4InfoByKey = new Map()

    for (const proxy of proxies) {
        const info = proxy._node_info
        if (!isValidNodeInfo(info) || !hasFraudScore(info) || isIPv6(info.ip)) {
            continue
        }
        ipv4InfoByKey.set(getDualStackKey(proxy), info)
    }

    for (const proxy of proxies) {
        const info = proxy._node_info
        if (!isValidNodeInfo(info) || hasFraudScore(info) || !isIPv6(info.ip)) {
            continue
        }

        const ipv4Info = ipv4InfoByKey.get(getDualStackKey(proxy))
        if (ipv4Info) {
            proxy._node_info = ipv4Info
            proxy._ippure = ipv4Info
        }
    }
}

function getDualStackKey(proxy = {}) {
    return [
        proxy._domain || proxy._originalServer || '',
        getOriginalName(proxy),
        proxy.port || '',
        proxy.type || '',
    ].join('|')
}

function isCacheComplete(cached = {}, udpEnabled) {
    return isValidNodeInfo(cached.info) && (!udpEnabled || Object.prototype.hasOwnProperty.call(cached, 'udp'))
}

function isValidNodeInfo(info) {
    return info && typeof info === 'object' && Boolean(info.ip || info.countryCode || info.country || info.asOrganization)
}

function hasFraudScore(info = {}) {
    return Object.prototype.hasOwnProperty.call(info, 'fraudScore') && info.fraudScore !== undefined && info.fraudScore !== null
}

function getPurityLabel(info = {}) {
    if (hasFraudScore(info)) {
        return String(info.fraudScore)
    }
    if (isIPv6(info.ip)) {
        return 'IPv6'
    }
    return '-'
}

function buildNodeTag(info = {}, udp = false) {
    const parts = [getPurityLabel(info), pickResidentialIcon(info.isResidential), pickBroadcastIcon(info.isBroadcast)]
    if (udp) {
        parts.push('UDP')
    }
    return `[${parts.join('|')}]`
}

function pickResidentialIcon(value) {
    return toBoolean(value) ? '🏠' : '🏢'
}

function pickBroadcastIcon(value) {
    return toBoolean(value) ? '🌱' : '📡'
}

function findMultiplier(name = '') {
    const text = normalizeText(name)
    const boundary = String.raw`(?:^|[\s_\-+~|/\\()[\]{}:：,，#])`
    const end = String.raw`(?=$|[\s_\-+~|/\\()[\]{}:：,，#倍])`
    const patterns = [
        new RegExp(`${boundary}[xX]\\s*([0-9]+(?:\\.[0-9]+)?)${end}`, 'g'),
        new RegExp(`${boundary}([0-9]+(?:\\.[0-9]+)?)\\s*[xX]${end}`, 'g'),
        new RegExp(`${boundary}([0-9]+(?:\\.[0-9]+)?)\\s*倍${end}`, 'g'),
    ]

    for (const pattern of patterns) {
        let match
        while ((match = pattern.exec(text))) {
            const multiplier = formatMultiplier(match[1])
            if (multiplier) {
                return multiplier
            }
        }
    }
    return ''
}

function formatMultiplier(value) {
    const number = Number(value)
    if (!Number.isFinite(number) || number <= 0 || Math.abs(number - 1) < 1e-9) {
        return ''
    }
    return String(number)
}

function createAsnLookup($, mmdbCountryPath, mmdbAsnPath) {
    try {
        if (typeof ProxyUtils === 'undefined' || !ProxyUtils.MMDB) {
            $.info('[MMDB] ProxyUtils.MMDB 不可用, 使用 IPPure API 的组织名称')
            return undefined
        }

        const utils = new ProxyUtils.MMDB({ country: mmdbCountryPath, asn: mmdbAsnPath })
        $.info('[MMDB] 启用 GeoIP/ASN 查询修正落地名称')

        return ip => {
            if (!ip) {
                return {}
            }

            return {
                countryCode: utils.geoip ? utils.geoip(ip) || '' : '',
                aso: utils.ipaso ? utils.ipaso(ip) || '' : '',
                asn: utils.ipasn ? utils.ipasn(ip) || '' : '',
            }
        }
    } catch (e) {
        $.info(`[MMDB] 初始化失败, 使用 IPPure API 的组织名称: ${e.message ?? e}`)
        return undefined
    }
}

function getOrganization(info = {}) {
    const values = [
        info.aso,
        info.asOrganization,
        info.isp,
        info.org,
        info.asname,
        info.as,
    ]

    for (const value of values) {
        const text = String(value ?? '').trim()
        if (text && !isGenericOrganization(text)) {
            return text
        }
    }

    if (info.asn) {
        return `AS${info.asn}`
    }

    return ''
}

function isGenericOrganization(value = '') {
    return /^(?:private customer|customer|unknown|anonymous|not available|n\/a)(?:\b|$)/i.test(String(value).trim())
}

function parseFrontProxy(value) {
    const raw = String(value || '').trim()
    if (!raw) {
        return undefined
    }

    const match = raw.match(/^([a-z][a-z0-9+.-]*):\/\/(?:([^@/?#]*)@)?(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?#].*)?$/i)
    if (!match) {
        throw new Error(`前置代理格式无效: ${raw}`)
    }

    const protocol = match[1].toLowerCase()
    const type = protocol === 'http' || protocol === 'https' ? 'http' : protocol === 'socks' || protocol === 'socks5' ? 'socks5' : ''
    if (!type) {
        throw new Error(`不支持的前置代理协议: ${protocol}`)
    }

    const auth = match[2] || ''
    const authParts = auth.split(':')

    return {
        name: 'front-proxy',
        type,
        server: match[3].replace(/^\[|\]$/g, ''),
        port: Number(match[4]),
        username: authParts[0] ? safeDecodeURIComponent(authParts[0]) : undefined,
        password: authParts.length > 1 ? safeDecodeURIComponent(authParts.slice(1).join(':')) : undefined,
        tls: protocol === 'https' ? true : undefined,
    }
}

function safeDecodeURIComponent(value) {
    try {
        return decodeURIComponent(value)
    } catch (e) {
        return value
    }
}

function firstText(...values) {
    for (const value of values) {
        const text = String(value ?? '').trim()
        if (text) {
            return text
        }
    }
    return ''
}

function getOriginalName(proxy = {}) {
    return String(proxy._originalName || proxy._rawName || proxy._name || proxy.name || '')
}

function hasOriginalName(proxy = {}) {
    return Boolean(proxy._originalName || proxy._rawName || proxy._name)
}

function getFlag(countryCode = '') {
    const code = String(countryCode || '').trim().toUpperCase()
    if (!/^[A-Z]{2}$/.test(code)) {
        return ''
    }

    try {
        if (typeof ProxyUtils !== 'undefined' && ProxyUtils.getFlag) {
            return ProxyUtils.getFlag(code).replace(/🇹🇼/g, '🇼🇸')
        }
    } catch (e) { }

    return code
        .replace(/[A-Z]/g, char => String.fromCodePoint(char.charCodeAt(0) + 127397))
        .replace(/🇹🇼/g, '🇼🇸')
}

function isIPv6(value = '') {
    return String(value || '').includes(':')
}

function normalizeText(value = '') {
    return String(value)
        .replace(/[０-９]/g, char => String.fromCharCode(char.charCodeAt(0) - 0xfee0))
        .replace(/[．。]/g, '.')
        .replace(/[ｘＸ×✕]/g, 'x')
}

function lodashGet(source, path, defaultValue = undefined) {
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

function getCacheId({ proxy = {}, url, udpEnabled, ntp, frontProxyUrl, asnLookupEnabled }) {
    return `http-meta:node-info:v2:${url}:${udpEnabled}:${ntp}:${frontProxyUrl || ''}:${asnLookupEnabled}:${JSON.stringify(
        Object.fromEntries(Object.entries(proxy).filter(([key]) => !/^(name|collectionName|subName|id|_.*)$/i.test(key)))
    )}`
}

function hasArgument(name) {
    return Object.prototype.hasOwnProperty.call($arguments, name)
}

function toBoolean(value) {
    if (value === undefined || value === null || value === '') {
        return false
    }
    return value === true || /^(true|1|yes|on)$/i.test(String(value))
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
