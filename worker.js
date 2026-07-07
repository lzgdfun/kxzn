const DEFAULT_BEIAN_CONTENT = `© 2025 - 2026 Check ProxyIP · 基于 <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" rel="noreferrer">Cloudflare Workers 构建与运行<[...]`;
const RESOLVE_BATCH_LIMIT = 15;
const CHECK_BATCH_LIMIT = 100;
const DEFAULT_CHECK_CONCURRENCY = 10;
const DEFAULT_IP_QUALITY_TIMEOUT_MS = 5000;
const DEFAULT_TARGETS_CSV_URL = 'https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv';
const DEFAULT_TARGETS_LIMIT = 20;
const CLEAN_PROXY_KV_KEYS = {
	results: 'checkproxy:clean_proxy_results',
	targets: 'checkproxy:clean_proxy_targets',
	meta: 'checkproxy:clean_proxy_meta'
};
const MANAGED_PROXY_KV_KEYS = {
	items: 'checkproxy:managed_proxy_items',
	settings: 'checkproxy:managed_proxy_settings'
};
const DEFAULT_PAGE_PASSWORD = 'wukong';
const DEFAULT_SUB_TOKEN = 'wukong';
const DEFAULT_NODE_TEMPLATE = 'vless://d0298536-d670-4045-bbb1-ddd5ea68683e@54.65.58.58:443?encryption=none&security=tls&sni=edcm.nrtpu.dpdns.org&fp=chrome&insecure=0&allowInsecure=0&ech=https%3A%[...]';

// ========== 关键修复：降低并发限制 ==========
// 原始值可能过高，导致子请求超限。Cloudflare Workers 默认允许约 50 个子请求
const OPTIMIZED_CHECK_CONCURRENCY = 4;  // 降低到 4（从原来的可能值）
const OPTIMIZED_BATCH_SIZE = 10;        // 每批检测 10 个 IP
const REQUEST_QUEUE_DELAY = 50;         // 请求队列延迟（毫秒）

export default {
	async fetch(request, env) {
		const 备案内容 = env.BEIAN ?? DEFAULT_BEIAN_CONTENT;
		const url = new URL(request.url);

		if (url.pathname === '/sub' || url.pathname.startsWith('/sub/')) {
			return handleSubscriptionRequest(request, env);
		} else if (url.pathname.startsWith('/api/')) {
			return handleManagedApiRequest(request, env);
		} else if (url.pathname === '/check') {
			return handleCheckProxyRequest(request, env);
		} else if (url.pathname === '/clean-proxies') {
			return handleCleanProxiesRequest(request, env);
		} else if (url.pathname === '/resolve') {
			const proxyip = url.searchParams.get('proxyip');
			if (!proxyip) {
				return new Response('Missing proxyip', { status: 400 });
			}

			try {
				const targets = await handleResolve(proxyip);
				return new Response(JSON.stringify(targets), {
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*'
					}
				});
			} catch (error) {
				return new Response(JSON.stringify({ error: error.message }), {
					status: 500,
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*'
					}
				});
			}
		} else if (url.pathname === '/resolve-batch') {
			return handleResolveBatchRequest(request);
		} else if (url.pathname === '/default-targets') {
			return handleDefaultTargetsRequest();
		} else if (url.pathname === '/locations') return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
		return new Response(generateHTML(备案内容), {
			headers: { 'Content-Type': 'text/html; charset=UTF-8' }
		});
	}
};

// ... (中间的代码保持不变，这里省略) ...

// ========== 关键修复：优化并发控制函数 ==========
async function mapWithConcurrencyOptimized(items, concurrency, mapper) {
	// 强制限制并发数，防止超过 Cloudflare 子请求限制
	const SAFE_CONCURRENCY = Math.min(concurrency, OPTIMIZED_CHECK_CONCURRENCY);
	const limit = Math.max(1, Math.min(SAFE_CONCURRENCY, items.length || 1));
	const results = new Array(items.length);
	let nextIndex = 0;

	await Promise.all(Array.from({ length: limit }, async () => {
		while (nextIndex < items.length) {
			const index = nextIndex++;
			// 添加请求间隔，避免请求堆积
			if (index > 0) {
				await new Promise(resolve => setTimeout(resolve, REQUEST_QUEUE_DELAY));
			}
			results[index] = await mapper(items[index], index);
		}
	}));

	return results;
}

// ========== 关键修复：分批检测函数 ==========
async function checkBatchJobsOptimized(checkJobs, run) {
	if (isRunStopped(run) || !checkJobs.length) return;
	
	// 按 OPTIMIZED_BATCH_SIZE 分批处理
	const batches = [];
	for (let i = 0; i < checkJobs.length; i += OPTIMIZED_BATCH_SIZE) {
		batches.push(checkJobs.slice(i, i + OPTIMIZED_BATCH_SIZE));
	}

	const itemByTarget = new Map(checkJobs.map(function (job) {
		return [job.target, job.itemObj];
	}));

	for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
		const batch = batches[batchIndex];
		if (isRunStopped(run)) break;

		try {
			progressText.innerText = `正在批量检测... 第 ${batchIndex + 1} / ${batches.length} 批`;
			const timeoutMs = Math.max(45000, batch.length * 10000); // 为每批分配足够时间
			
			const result = await fetchJsonWithTimeout('/check', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					targets: batch.map(function (job) { return job.target; }),
					resolve: false,
					purity: true,
					store: false, // 分批时先不写入，最后统一写入
					limit: batch.length,
					concurrency: OPTIMIZED_CHECK_CONCURRENCY // 使用优化后的并发数
				})
			}, timeoutMs, run?.controller.signal);
			throwIfRunStopped(run);

			const payload = result.payload || {};
			const batchResults = Array.isArray(payload.results) ? payload.results : [payload];
			const seenTargets = new Set();

			batchResults.forEach(function (data) {
				const target = data.candidate || data.target || data.input;
				const itemObj = itemByTarget.get(target) || itemByTarget.get(data.input);
				if (!itemObj) return;
				seenTargets.add(itemObj.record?.target || target);
				if (!result.response.ok) {
					data.success = false;
					data.message = data.message || data.error || ('HTTP ' + result.response.status);
				}
				completedCount++;
				applyCheckResult(itemObj.record?.target || target, itemObj, data);
			});

			batch.forEach(function (job) {
				if (seenTargets.has(job.target)) return;
				completedCount++;
				applyCheckResult(job.target, job.itemObj, {
					success: false,
					message: payload.error || '批量检测接口未返回该目标结果'
				});
			});

			// 批次之间的延迟，让 Workers 有时间恢复
			if (batchIndex < batches.length - 1) {
				await new Promise(resolve => setTimeout(resolve, 100));
			}
		} catch (error) {
			batch.forEach(function (job) {
				if (isRunStopped(run)) {
					if (job.itemObj.record) job.itemObj.record.status = 'stopped';
					job.itemObj.badge.className = 'status-badge status-error';
					job.itemObj.badge.innerText = '已停止';
					job.itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						buildCopyableTarget(job.target) +
						'<span class="result-detail">检测已手动停止，未继续请求该目标。</span>';
					job.itemObj.meta.innerHTML = buildMetaChip('已停止', 'info');
					job.itemObj.exitList.innerHTML = '';
					return;
				}
				completedCount++;
				applyCheckResult(job.target, job.itemObj, {
					success: false,
					message: error && error.name === 'AbortError' ? '批量检测请求超时' : '批量检测请求异常'
				});
			});
		}

		updateProgress();
		updateResultFilters();
	}
}

// ========== 其他代码保持原样 ==========
function jsonResponse(payload, status = 200, extraHeaders = {}) {
	return new Response(JSON.stringify(payload), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, X-Page-Password',
			...extraHeaders
		}
	});
}

// ... (后续代码继续保持不变) ...
