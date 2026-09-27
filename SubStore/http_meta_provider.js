/**
 * Sub-Store Node.js: request the egress IP, then resolve the AS organization via MMDB.
 * api: https://api.ip.sb/ip (plain IP or JSON with an ip field); method: get.
 * mmdb_country/mmdb_asn: local MMDB paths; node_info: keep _provider.
 * Never uses proxy.server as the egress IP or marks/removes a node as failed.
 * See README.md for shared HTTP META arguments.
 */
async function operator(proxies = [], targetPlatform, context) {
    const api = $arguments.api || 'https://api.ip.sb/ip'
    const method = String($arguments.method || 'get').toLowerCase()
    const country = $arguments.mmdb_country || '/opt/app/data/GeoLite2-Country.mmdb'
    const asn = $arguments.mmdb_asn || '/opt/app/data/GeoLite2-ASN.mmdb'
    const keepInfo = toBoolean($arguments.node_info)
    let mmdb
    proxies.forEach(proxy => {
        proxy._originalName = proxy._originalName || proxy.name
        proxy._originalServer = proxy._originalServer || proxy.server
        delete proxy._provider
    })
    await runChecks(proxies, ['provider', api, method, country, asn], async port => {
        const res = await http({
            url: api, method,
            proxy: `http://${$arguments.http_meta_host ?? '127.0.0.1'}:${port}`,
            headers: { 'User-Agent': 'Sub-Store-Node-Info' },
        })
        let body = res.body
        if (typeof body === 'string') {
            try { body = JSON.parse(body) } catch (_) { /* Plain-IP APIs are supported. */ }
        }
        const ip = String(typeof body === 'object' && body ? body.ip ?? '' : body ?? '').trim()
        if (!require('net').isIP(ip)) throw new Error('API 未返回有效出口 IP')
        if (!mmdb) mmdb = new ProxyUtils.MMDB({ country, asn })
        return { ip, aso: mmdb.ipaso(ip) || '', asn: mmdb.ipasn(ip) || '', countryCode: mmdb.geoip(ip) || '' }
    }, (proxy, result) => {
        if (!result.ok) return
        const info = result.data
        if (keepInfo) proxy._provider = info
        const organization = getOrganization(info)
        if (!organization) return
        const match = String(proxy.name).match(/^\[([^\]]*)\]\s*/)
        const tags = match ? match[1].split('|').filter(tag => tag && !/^x\d+(?:\.\d+)?$/.test(tag)) : []
        const multiplier = findMultiplier(proxy._originalName)
        if (multiplier) tags.push(`x${multiplier}`)
        const flag = getFlag(info.countryCode)
        proxy.name = `${tags.length ? `[${tags.join('|')}] ` : ''}${[flag, organization].filter(Boolean).join(' ')}`
    })
    return finish(proxies)
}

function getOrganization(info) {
    const aso = String(info.aso || '').trim()
    if (aso && !/^(?:private customer|customer|unknown|anonymous|not available|n\/a)(?:\b|$)/i.test(aso)) return aso
    return info.asn ? `AS${String(info.asn).replace(/^AS/i, '')}` : ''
}

function findMultiplier(name = '') {
    const text = String(name)
        .replace(/[０-９]/g, char => String.fromCharCode(char.charCodeAt(0) - 0xfee0))
        .replace(/[．。]/g, '.')
        .replace(/[ｘＸ×✕]/g, 'x')
    const boundary = String.raw`(?:^|[\s_\-+~|/\\()[\]{}:：,，#])`
    const end = String.raw`(?=$|[\s_\-+~|/\\()[\]{}:：,，#倍])`
    for (const pattern of [
        new RegExp(`${boundary}[xX]\\s*([0-9]+(?:\\.[0-9]+)?)${end}`, 'g'),
        new RegExp(`${boundary}([0-9]+(?:\\.[0-9]+)?)\\s*[xX]${end}`, 'g'),
        new RegExp(`${boundary}([0-9]+(?:\\.[0-9]+)?)\\s*倍${end}`, 'g'),
    ]) {
        for (const match of text.matchAll(pattern)) {
            const value = Number(match[1])
            if (Number.isFinite(value) && value > 0 && Math.abs(value - 1) >= 1e-9) return String(value)
        }
    }
    return ''
}

function getFlag(value) {
    const code = String(value || '').trim().toUpperCase()
    if (!/^[A-Z]{2}$/.test(code)) return ''
    return code.replace(/[A-Z]/g, char => String.fromCodePoint(char.charCodeAt(0) + 127397)).replace(/🇹🇼/g, '🇼🇸')
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
