/**
 * Sub-Store Node.js: URL availability check (the only node-failure gate).
 * url: https://www.gstatic.com/generate_204; method: get; HTTP 200–399 succeeds.
 * remove_failed: remove failed nodes; node_info: keep _check_failed/_latency.
 * remove_incompatible: independently remove nodes unsupported by ClashMeta.
 * See README.md for shared HTTP META arguments.
 */
async function operator(proxies = [], targetPlatform, context) {
    const url = $arguments.url || 'https://www.gstatic.com/generate_204'
    const method = String($arguments.method || 'get').toLowerCase()
    proxies.forEach(proxy => {
        delete proxy._check_failed
        delete proxy._latency
    })
    await runChecks(proxies, ['availability', url, method], async port => {
        const startedAt = Date.now()
        await http({
            url, method,
            proxy: `http://${$arguments.http_meta_host ?? '127.0.0.1'}:${port}`,
        })
        return { latency: Date.now() - startedAt }
    }, (proxy, result) => {
        proxy._check_failed = !result.ok
        if (result.ok) proxy._latency = result.data.latency
    })
    const result = proxies.filter(proxy =>
        !(toBoolean($arguments.remove_failed) && proxy._check_failed === true) &&
        !(toBoolean($arguments.remove_incompatible) && proxy._incompatible))
    if (!toBoolean($arguments.node_info)) {
        result.forEach(proxy => {
            delete proxy._check_failed
            delete proxy._latency
        })
    }
    return finish(result)
}

// Kept inline so this file can be used as a standalone Sub-Store script.
async function runChecks(proxies, cacheKey, check, apply) {
    const $ = $substore
    const cache = toBoolean($arguments.cache) ? scriptResourceCache : undefined
    const retryFailed = toBoolean($arguments.disable_failed_cache || $arguments.ignore_failed_error)
    const frontUrl = $arguments.dialer_proxy || $arguments.front_proxy || $arguments.upstream_proxy
    const pending = []

    for (const proxy of proxies) {
        delete proxy._incompatible
        let node
        try {
            node = ProxyUtils.produce([{ ...proxy }], 'ClashMeta', 'internal', {
                'include-unsupported-proxy': toBoolean($arguments.include_unsupported_proxy),
            })?.[0]
        } catch (error) {
            $.error(`[${proxy.name}] ${error.message ?? error}`)
        }
        if (!node) {
            proxy._incompatible = true
            continue
        }
        const identity = Object.fromEntries(Object.entries(node)
            .filter(([key]) => !/^(name|collectionName|subName|id|_.*)$/i.test(key)))
        const key = `http-meta:standalone:v1:${JSON.stringify([cacheKey, frontUrl || '', identity])}`
        const cached = cache?.get(key)
        if (cached && (cached.ok === true || (cached.ok === false && !retryFailed))) {
            apply(proxy, cached)
        } else {
            pending.push({ proxy, node, key })
        }
    }
    if (!pending.length) return

    const front = parseFrontProxy(frontUrl)
    const nodes = pending.map(({ node }) => front ? { ...node, 'dialer-proxy': `proxy-${pending.length}` } : node)
    if (front) nodes.push(front)
    const startDelay = Math.max(0, Number($arguments.http_meta_start_delay ?? 3000))
    const proxyTimeout = Math.max(1, Number($arguments.http_meta_proxy_timeout ?? 10000))
    let pid
    try {
        const res = await http({
            method: 'post', url: metaUrl('/start'), retries: 0, headers: metaHeaders(),
            body: JSON.stringify({ proxies: nodes, timeout: startDelay + pending.length * proxyTimeout }),
        })
        const body = typeof res.body === 'string' ? JSON.parse(res.body) : res.body
        pid = body?.pid
        if (!pid || !Array.isArray(body?.ports) || body.ports.length < nodes.length ||
            body.ports.some(port => !Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535)) {
            throw new Error('HTTP META 启动失败：缺少有效 pid/ports')
        }
        $.info(`[HTTP META] PID ${pid}，待检测节点 ${pending.length}`)
        await $.wait(startDelay)
        let index = 0
        const concurrency = Math.max(1, parseInt($arguments.concurrency || 10) || 10)
        await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) }, async () => {
            while (index < pending.length) {
                const current = index++
                const { proxy, key } = pending[current]
                let result
                try {
                    result = { ok: true, data: await check(body.ports[current]) }
                } catch (error) {
                    result = { ok: false }
                    $.info(`[${proxy.name}] ${cacheKey[0]} 检测未成功: ${error.message ?? error}`)
                }
                apply(proxy, result)
                cache?.set(key, result)
            }
        }))
    } finally {
        if (pid) {
            try {
                await http({
                    method: 'post', url: metaUrl('/stop'), headers: metaHeaders(),
                    body: JSON.stringify({ pid: [pid] }),
                })
            } catch (error) {
                $.error(`[HTTP META] 关闭失败: ${error.message ?? error}`)
            }
        }
    }
}

async function http(options) {
    const method = String(options.method || 'get').toLowerCase()
    const timeout = Number(options.timeout ?? $arguments.timeout ?? 5000)
    const retries = Math.max(0, parseInt(options.retries ?? $arguments.retries ?? 1) || 0)
    for (let attempt = 0; ; attempt++) {
        try {
            const res = await $substore.http[method]({ ...options, timeout })
            const status = Number(res.statusCode ?? res.status)
            if (!(status >= 200 && status < 400)) throw new Error(`HTTP ${status}`)
            return res
        } catch (error) {
            if (attempt >= retries) throw error
            await $substore.wait(Number($arguments.retry_delay ?? 1000) * (attempt + 1))
        }
    }
}

function metaUrl(path) {
    return `${$arguments.http_meta_protocol ?? 'http'}://${$arguments.http_meta_host ?? '127.0.0.1'}:${$arguments.http_meta_port ?? 9876}${path}`
}

function metaHeaders() {
    return { 'Content-Type': 'application/json', Authorization: $arguments.http_meta_authorization ?? '' }
}

function parseFrontProxy(value) {
    if (!value) return undefined
    const match = String(value).trim().match(/^([a-z][a-z0-9+.-]*):\/\/(?:([^@/?#]*)@)?(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?#].*)?$/i)
    if (!match) throw new Error('前置代理 URL 格式无效')
    const protocol = match[1].toLowerCase()
    const type = ['http', 'https'].includes(protocol) ? 'http' : ['socks', 'socks5'].includes(protocol) ? 'socks5' : ''
    if (!type) throw new Error(`不支持的前置代理协议: ${protocol}`)
    const auth = (match[2] || '').split(':')
    return {
        name: 'front-proxy', type, server: match[3].replace(/^\[|\]$/g, ''), port: Number(match[4]),
        username: auth[0] ? decodeURIComponent(auth[0]) : undefined,
        password: auth.length > 1 ? decodeURIComponent(auth.slice(1).join(':')) : undefined,
        tls: protocol === 'https' ? true : undefined,
    }
}

function toBoolean(value) {
    return value === true || /^(true|1|yes|on)$/i.test(String(value ?? ''))
}

function finish(proxies) {
    if (!toBoolean($arguments.incompatible)) proxies.forEach(proxy => { delete proxy._incompatible })
    return proxies
}
