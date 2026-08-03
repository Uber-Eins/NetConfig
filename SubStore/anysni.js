/**
 * AnyTLS SNI + SHA-256 certificate pin operator for Sub-Store Node.js.
 *
 * Arguments:
 * - sni: required. SNI to write to every AnyTLS node, e.g. cute.neko
 * - timeout: TLS handshake timeout in ms, default 7000
 * - concurrency: concurrent probes, default 6
 * - retries: retry count after the first attempt, default 1
 * - retry_delay: base retry delay in ms, default 500
 * - cache: use scriptResourceCache, default false
 * - cache_ttl: successful cache lifetime in ms, default 86400000 (24 h)
 * - force: ignore cached fingerprint, default false
 * - strict: reject a changed fingerprint instead of replacing it, default false
 * - remove_failed: remove AnyTLS nodes whose certificate cannot be obtained, default false
 * - alpn: optional comma-separated ALPN list, e.g. h2,http/1.1
 * - frontProxy/front_proxy/dialer_proxy/upstream_proxy: HTTP(S) or SOCKS5 front proxy URL
 *
 * Example:
 * #sni=cute.neko&timeout=7000&concurrency=6&cache=true
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore
    const desiredSni = String($arguments.sni ?? '').trim()

    if (!desiredSni) {
        throw new Error('缺少必要參數 sni，例如：#sni=cute.neko')
    }

    if (typeof require !== 'function') {
        throw new Error(
            '此腳本需要 Sub-Store Node.js 版提供 require()，無法在純代理 App 腳本環境中直接執行'
        )
    }

    const tls = require('tls')
    const crypto = require('crypto')
    const net = require('net')
    const http = require('http')
    const https = require('https')

    const timeout = positiveInteger($arguments.timeout, 7000)
    const concurrency = positiveInteger($arguments.concurrency, 6)
    const retries = nonNegativeInteger($arguments.retries, 1)
    const retryDelay = nonNegativeInteger($arguments.retry_delay, 500)
    const cacheEnabled = toBoolean($arguments.cache)
    const cacheTtl = positiveInteger(
        $arguments.cache_ttl,
        24 * 60 * 60 * 1000
    )
    const force = toBoolean($arguments.force)
    const strict = toBoolean($arguments.strict)
    const removeFailed = toBoolean($arguments.remove_failed)
    const alpn = parseList($arguments.alpn)
    const frontProxyUrl = $arguments.frontProxy || $arguments.front_proxy || $arguments.dialer_proxy || $arguments.upstream_proxy
    const frontProxy = parseFrontProxy(frontProxyUrl)

    const cache =
        typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache
            : undefined

    const targets = []
    const failedIndexes = new Set()

    let totalAnyTls = 0
    let successCount = 0
    const probePromises = new Map()

    proxies.forEach((proxy, index) => {
        if (String(proxy?.type ?? '').toLowerCase() !== 'anytls') {
            return
        }

        totalAnyTls++

        const server = normalizeHost(proxy.server)
        const port = Number(proxy.port)

        const oldFingerprint = normalizeFingerprint(
            proxy['tls-fingerprint'] ?? proxy.fingerprint
        )

        /*
         * AnyTLS 在 mihomo 輸出中使用 sni。
         * 移除可能由其他格式帶入的 servername，
         * 避免同時存在兩個不一致的欄位。
         */
        proxy.sni = desiredSni
        delete proxy.servername

        if (!server) {
            $.error(
                `[${proxy.name ?? index}] 缺少 server，無法取得 TLS 證書`
            )
            failedIndexes.add(index)
            return
        }

        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            $.error(
                `[${proxy.name ?? index}] 無效 port：${proxy.port}`
            )
            failedIndexes.add(index)
            return
        }

        targets.push({
            proxy,
            index,
            name: proxy.name || `${server}:${port}`,
            server,
            port,
            oldFingerprint,
        })
    })

    if (!targets.length) {
        $.info('沒有找到 AnyTLS 節點')
        return proxies
    }

    $.info(
        `AnyTLS 節點：${targets.length}，SNI → ${desiredSni}`
    )

    const tasks = targets.map(target => async () => {
        const cacheKey = makeCacheKey(
            desiredSni,
            alpn,
            frontProxyUrl
        )

        let result
        let fromCache = false
        let referenceFingerprint = target.oldFingerprint

        if (cacheEnabled && cache && !force) {
            try {
                const cached = cache.get(cacheKey)

                const cachedFingerprint = normalizeFingerprint(
                    cached?.fingerprint
                )

                if (cachedFingerprint) {
                    referenceFingerprint =
                        referenceFingerprint || cachedFingerprint
                }

                if (
                    cachedFingerprint &&
                    Number(cached.expiresAt) > Date.now()
                ) {
                    result = {
                        ...cached,
                        fingerprint: cachedFingerprint,
                    }

                    fromCache = true

                    $.info(
                        `[${target.name}] 使用證書指紋快取`
                    )
                }
            } catch (error) {
                $.error(
                    `[${target.name}] 讀取證書指紋快取失敗：${error?.message ?? error
                    }`
                )
            }
        }

        if (!result) {
            try {
                const probeKey = `${desiredSni}\0${alpn.join(',')}\0${frontProxyUrl || ''}`
                if (!probePromises.has(probeKey)) {
                    probePromises.set(probeKey, retry(
                        () => readLeafCertificate({
                            tls,
                            crypto,
                            net,
                            http,
                            https,
                            host: target.server,
                            port: target.port,
                            servername: desiredSni,
                            timeout,
                            alpn,
                            frontProxy,
                        }),
                        retries,
                        retryDelay
                    ))
                }
                result = await probePromises.get(probeKey)
            } catch (error) {
                failedIndexes.add(target.index)

                $.error(
                    `[${target.name}] TLS 證書取得失敗：${error?.message ?? error
                    }`
                )

                return
            }
        }

        const fingerprint = normalizeFingerprint(
            result.fingerprint
        )

        if (!fingerprint) {
            failedIndexes.add(target.index)

            $.error(
                `[${target.name}] 取得了無效的 SHA-256 指紋`
            )

            return
        }

        if (
            strict &&
            referenceFingerprint &&
            referenceFingerprint !== fingerprint
        ) {
            /*
             * strict=true 時，不允許探測結果靜默取代已知 pin。
             * 保留舊指紋，並將該節點標記為失敗。
             */
            target.proxy['tls-fingerprint'] =
                referenceFingerprint

            delete target.proxy.fingerprint

            failedIndexes.add(target.index)

            $.error(
                `[${target.name}] 證書指紋已變更，` +
                `strict=true，保留舊值\n` +
                `舊：${referenceFingerprint}\n` +
                `新：${fingerprint}`
            )

            return
        }

        /*
         * Sub-Store 內部使用 tls-fingerprint。
         * 輸出 Clash Meta / mihomo 時會轉為 fingerprint。
         */
        target.proxy['tls-fingerprint'] = fingerprint

        delete target.proxy.fingerprint

        if (cacheEnabled && cache && !fromCache) {
            try {
                const certificateExpiry = parseDate(
                    result.validTo
                )

                const expiresAt = Math.min(
                    Date.now() + cacheTtl,
                    certificateExpiry > Date.now()
                        ? Math.max(
                            Date.now(),
                            certificateExpiry -
                            60 * 60 * 1000
                        )
                        : Date.now() + cacheTtl
                )

                cache.set(cacheKey, {
                    fingerprint,
                    validTo: result.validTo,
                    expiresAt,
                })
            } catch (error) {
                $.error(
                    `[${target.name}] 寫入證書指紋快取失敗：${error?.message ?? error
                    }`
                )
            }
        }

        successCount++

        $.info(
            `[${target.name}] ` +
            `${target.server}:${target.port} ` +
            `SNI=${desiredSni} ` +
            `SHA256=${fingerprint}` +
            (result.validTo
                ? ` 有效至=${result.validTo}`
                : '')
        )
    })

    await executeAsyncTasks(tasks, {
        concurrency,
    })

    $.info(
        `AnyTLS 證書指紋完成：成功 ${successCount}，` +
        `失敗 ${totalAnyTls - successCount}`
    )

    if (removeFailed && failedIndexes.size) {
        return proxies.filter(
            (_, index) => !failedIndexes.has(index)
        )
    }

    return proxies
}

async function readLeafCertificate({
    tls,
    crypto,
    net,
    http,
    https,
    host,
    port,
    servername,
    timeout,
    alpn,
    frontProxy,
}) {
    const tunnel = frontProxy
        ? await openProxyTunnel({ net, http, https, proxy: frontProxy, host, port, timeout })
        : undefined

    return new Promise((resolve, reject) => {
        let settled = false
        let socket

        const finish = (error, value) => {
            if (settled) {
                return
            }

            settled = true

            if (socket) {
                socket.destroy()
            }

            if (error) {
                reject(error)
            } else {
                resolve(value)
            }
        }

        const options = {
            ...(tunnel ? { socket: tunnel } : { host, port }),
            servername,

            /*
             * 這條 TLS 連線的用途是讀取證書，
             * 真正的信任依據是之後寫入的 SHA-256 pin。
             *
             * 因此必須允許自簽證書、未知 CA，
             * 以及 SNI 與 SAN/CN 不一致的證書。
             */
            rejectUnauthorized: false,
        }

        if (alpn.length) {
            options.ALPNProtocols = alpn
        }

        try {
            socket = tls.connect(options)
        } catch (error) {
            finish(error)
            return
        }

        socket.setTimeout(timeout, () => {
            finish(
                new Error(
                    `TLS 握手逾時（${timeout} ms）`
                )
            )
        })

        socket.once('secureConnect', () => {
            try {
                const cert =
                    socket.getPeerCertificate(false)

                if (!cert || !cert.raw) {
                    throw new Error(
                        '伺服器未提供可讀取的葉證書'
                    )
                }

                /*
                 * 對完整 DER 編碼的葉證書計算 SHA-256。
                 * 這與 mihomo 的 certificate fingerprint
                 * 格式相符，不是 SPKI pin。
                 */
                const fingerprint = crypto
                    .createHash('sha256')
                    .update(cert.raw)
                    .digest('hex')
                    .toLowerCase()

                finish(null, {
                    fingerprint,
                    validTo: cert.valid_to || '',
                })
            } catch (error) {
                finish(error)
            }
        })

        socket.once('error', error => {
            finish(error)
        })

        socket.once('end', () => {
            if (!settled) {
                finish(
                    new Error(
                        'TLS 連線在握手完成前關閉'
                    )
                )
            }
        })
    })
}

async function retry(task, retries, retryDelay) {
    let lastError

    for (
        let attempt = 0;
        attempt <= retries;
        attempt++
    ) {
        try {
            return await task()
        } catch (error) {
            lastError = error

            if (
                attempt < retries &&
                retryDelay > 0
            ) {
                await sleep(
                    retryDelay * (attempt + 1)
                )
            }
        }
    }

    throw lastError
}

function executeAsyncTasks(
    tasks,
    {
        concurrency = 1,
    } = {}
) {
    return new Promise((resolve, reject) => {
        let running = 0
        let index = 0
        let completed = 0
        let rejected = false

        const next = () => {
            if (rejected) {
                return
            }

            if (completed === tasks.length) {
                resolve()
                return
            }

            while (
                running < concurrency &&
                index < tasks.length
            ) {
                const task = tasks[index++]

                running++

                Promise.resolve()
                    .then(task)
                    .catch(error => {
                        rejected = true
                        reject(error)
                    })
                    .finally(() => {
                        running--
                        completed++
                        next()
                    })
            }
        }

        next()
    })
}

function parseFrontProxy(value) {
    const raw = String(value ?? '').trim()
    if (!raw) return undefined

    let url
    try {
        url = new URL(raw)
    } catch (error) {
        throw new Error(`前置代理格式无效：${raw}`)
    }

    const protocol = url.protocol.replace(':', '').toLowerCase()
    if (!['http', 'https', 'socks5', 'socks'].includes(protocol)) {
        throw new Error(`不支持的前置代理协议：${protocol}`)
    }

    return {
        protocol: protocol === 'socks' ? 'socks5' : protocol,
        host: url.hostname,
        port: Number(url.port || (protocol === 'https' ? 443 : 1080)),
        username: decodeURIComponent(url.username || ''),
        password: decodeURIComponent(url.password || ''),
    }
}

function openProxyTunnel({ net, http, https, proxy, host, port, timeout }) {
    if (proxy.protocol === 'socks5') {
        return openSocks5Tunnel({ net, proxy, host, port, timeout })
    }

    return new Promise((resolve, reject) => {
        const transport = proxy.protocol === 'https' ? https : http
        const headers = { Host: `${host}:${port}` }
        if (proxy.username || proxy.password) {
            headers['Proxy-Authorization'] = `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}`
        }
        const request = transport.request({
            host: proxy.host,
            port: proxy.port,
            method: 'CONNECT',
            path: `${host}:${port}`,
            headers,
            timeout,
            rejectUnauthorized: false,
        })
        request.once('connect', (response, socket, head) => {
            if (response.statusCode !== 200) {
                socket.destroy()
                reject(new Error(`HTTP 前置代理 CONNECT 失败：${response.statusCode}`))
                return
            }
            if (head.length) socket.unshift(head)
            resolve(socket)
        })
        request.once('timeout', () => request.destroy(new Error(`前置代理连接逾时（${timeout} ms）`)))
        request.once('error', reject)
        request.end()
    })
}

function openSocks5Tunnel({ net, proxy, host, port, timeout }) {
    return new Promise((resolve, reject) => {
        const socket = net.connect(proxy.port, proxy.host)
        let buffer = Buffer.alloc(0)
        let stage = 0

        const fail = error => {
            socket.destroy()
            reject(error instanceof Error ? error : new Error(String(error)))
        }
        const sendConnect = () => {
            const hostBuffer = Buffer.from(host)
            if (hostBuffer.length > 255) return fail('SOCKS5 目标主机名过长')
            const request = Buffer.alloc(7 + hostBuffer.length)
            request.set([5, 1, 0, 3, hostBuffer.length], 0)
            hostBuffer.copy(request, 5)
            request.writeUInt16BE(port, 5 + hostBuffer.length)
            socket.write(request)
        }
        const consume = length => {
            const value = buffer.subarray(0, length)
            buffer = buffer.subarray(length)
            return value
        }
        const process = () => {
            if (stage === 0 && buffer.length >= 2) {
                const reply = consume(2)
                if (reply[0] !== 5 || reply[1] === 0xff) return fail('SOCKS5 前置代理拒绝认证方式')
                if (reply[1] === 2) {
                    const user = Buffer.from(proxy.username)
                    const pass = Buffer.from(proxy.password)
                    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]))
                    stage = 1
                } else {
                    stage = 2
                    sendConnect()
                }
            }
            if (stage === 1 && buffer.length >= 2) {
                const reply = consume(2)
                if (reply[1] !== 0) return fail('SOCKS5 前置代理认证失败')
                stage = 2
                sendConnect()
            }
            if (stage === 2 && buffer.length >= 5) {
                const addressType = buffer[3]
                const addressLength = addressType === 1 ? 4 : addressType === 4 ? 16 : addressType === 3 && buffer.length >= 5 ? 1 + buffer[4] : 0
                if (!addressLength || buffer.length < 4 + addressLength + 2) return
                const reply = consume(4 + addressLength + 2)
                if (reply[1] !== 0) return fail(`SOCKS5 CONNECT 失败：${reply[1]}`)
                socket.removeAllListeners('data')
                socket.setTimeout(0)
                if (buffer.length) socket.unshift(buffer)
                resolve(socket)
            }
        }

        socket.setTimeout(timeout, () => fail(`前置代理连接逾时（${timeout} ms）`))
        socket.once('error', fail)
        socket.once('connect', () => {
            const methods = proxy.username || proxy.password ? [0, 2] : [0]
            socket.write(Buffer.from([5, methods.length, ...methods]))
        })
        socket.on('data', chunk => {
            buffer = Buffer.concat([buffer, chunk])
            process()
        })
    })
}

function makeCacheKey(
    sni,
    alpn,
    frontProxyUrl
) {
    return (
        `anytls-cert-sha256:v2:` +
        `${sni}:${alpn.join(',')}:` +
        `${frontProxyUrl || ''}`
    )
}

function normalizeHost(value) {
    const host = String(value ?? '').trim()

    if (
        host.startsWith('[') &&
        host.endsWith(']')
    ) {
        return host.slice(1, -1)
    }

    return host
}

function normalizeFingerprint(value) {
    const fingerprint = String(value ?? '')
        .trim()
        .replace(/:/g, '')
        .toLowerCase()

    return /^[0-9a-f]{64}$/.test(fingerprint)
        ? fingerprint
        : ''
}

function parseList(value) {
    if (Array.isArray(value)) {
        return value
            .map(item =>
                String(item).trim()
            )
            .filter(Boolean)
    }

    return String(value ?? '')
        .split(',')
        .map(item => item.trim())
        .filter(Boolean)
}

function parseDate(value) {
    const timestamp = Date.parse(
        String(value ?? '')
    )

    return Number.isFinite(timestamp)
        ? timestamp
        : 0
}

function positiveInteger(value, fallback) {
    const number = Number(value)

    return Number.isInteger(number) &&
        number > 0
        ? number
        : fallback
}

function nonNegativeInteger(
    value,
    fallback
) {
    const number = Number(value)

    return Number.isInteger(number) &&
        number >= 0
        ? number
        : fallback
}

function toBoolean(value) {
    return (
        value === true ||
        /^(true|1|yes|on)$/i.test(
            String(value ?? '').trim()
        )
    )
}

function sleep(ms) {
    return new Promise(resolve =>
        setTimeout(resolve, ms)
    )
}
