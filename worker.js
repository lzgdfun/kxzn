const DEFAULT_BEIAN_CONTENT = `© 2025 - 2026 Check ProxyIP · 基于 <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" rel="noreferrer">Cloudflare Workers 构建与运行</a>`;
const RESOLVE_BATCH_LIMIT = 15;
const CHECK_BATCH_LIMIT = 100;
const DEFAULT_CHECK_CONCURRENCY = 10;
const DEFAULT_IP_QUALITY_TIMEOUT_MS = 5000;
const DEFAULT_TARGETS_CSV_URL = 'https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv';
const DEFAULT_TARGETS_LIMIT = 20;
const MANAGED_PROXY_KV_KEYS = {
	items: 'checkproxy:managed_proxy_items',
	settings: 'checkproxy:managed_proxy_settings'
};
const DEFAULT_PAGE_PASSWORD = 'wukong';
const DEFAULT_SUB_TOKEN = 'wukong';
const DEFAULT_NODE_TEMPLATE = 'vless://d0298536-d670-4045-bbb1-ddd5ea68683e@54.65.58.58:443?encryption=none&security=tls&sni=edcm.nrtpu.dpdns.org&fp=chrome&insecure=0&allowInsecure=0&ech=https%3A%[...]';

// ========== 批量检测参数配置 ==========
// 这些可以在前端配置面板中调整
const DEFAULT_BATCH_SIZE = 20;      // 前端分批大小，n = 20 个/批
const DEFAULT_WORKER_CONCURRENCY = 3; // Worker 内部并发数，m = 3
const REQUEST_QUEUE_DELAY = 50;     // 请求队列延迟（毫秒）

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

// ========== 优化并发控制函数 ==========
async function mapWithConcurrencyOptimized(items, concurrency, mapper) {
	// 强制限制并发数，防止超过 Cloudflare 子请求限制
	const SAFE_CONCURRENCY = Math.min(concurrency, DEFAULT_WORKER_CONCURRENCY);
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

// ========== 分批检测函数（仅保留 IPPure 系数检测）==========
async function checkBatchJobsOptimized(checkJobs, run, batchSize = DEFAULT_BATCH_SIZE, workerConcurrency = DEFAULT_WORKER_CONCURRENCY) {
	if (isRunStopped(run) || !checkJobs.length) return;
	
	// 按指定的 batchSize 分批处理
	const batches = [];
	for (let i = 0; i < checkJobs.length; i += batchSize) {
		batches.push(checkJobs.slice(i, i + batchSize));
	}

	const itemByTarget = new Map(checkJobs.map(function (job) {
		return [job.target, job.itemObj];
	}));

	for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
		const batch = batches[batchIndex];
		if (isRunStopped(run)) break;

		try {
			progressText.innerText = `正在批量检测... 第 ${batchIndex + 1} / ${batches.length} 批 (批大小: ${batchSize}, 并发: ${workerConcurrency})`;
			const timeoutMs = Math.max(45000, batch.length * 10000); // 为每批分配足够时间
			
			// 仅检测 IPPure 系数，不检测 IP 纯净度
			const result = await fetchJsonWithTimeout('/check', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					targets: batch.map(function (job) { return job.target; }),
					resolve: false,
					purity: false,  // 禁用 IP 纯净度检测
					store: false,   // 分批时先不写入，最后统一写入
					limit: batch.length,
					concurrency: workerConcurrency // 使用配置的并发数
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

// ========== 响应函数 ==========
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

// ========== 前端 HTML 生成函数 ==========
function generateHTML(beianContent) {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Check ProxyIP</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}
		
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh;
			padding: 20px;
		}
		
		.container {
			max-width: 1200px;
			margin: 0 auto;
		}
		
		.header {
			text-align: center;
			color: white;
			margin-bottom: 40px;
		}
		
		.header h1 {
			font-size: 2.5em;
			margin-bottom: 10px;
		}
		
		.main-panel {
			background: white;
			border-radius: 12px;
			padding: 30px;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
			margin-bottom: 30px;
		}
		
		.ip-input {
			display: flex;
			gap: 10px;
			margin-bottom: 20px;
		}
		
		.ip-input input {
			flex: 1;
			padding: 12px;
			border: 2px solid #e0e0e0;
			border-radius: 6px;
			font-size: 16px;
			transition: border-color 0.3s;
		}
		
		.ip-input input:focus {
			outline: none;
			border-color: #667eea;
		}
		
		.ip-input button {
			padding: 12px 24px;
			background: #667eea;
			color: white;
			border: none;
			border-radius: 6px;
			font-size: 16px;
			cursor: pointer;
			transition: background 0.3s;
		}
		
		.ip-input button:hover {
			background: #764ba2;
		}
		
		.results {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
			gap: 20px;
			margin-top: 20px;
		}
		
		.result-card {
			background: #f5f5f5;
			padding: 20px;
			border-radius: 8px;
			border-left: 4px solid #667eea;
		}
		
		.result-card h3 {
			margin-bottom: 10px;
			color: #333;
		}
		
		.result-card p {
			font-size: 14px;
			color: #666;
			margin: 5px 0;
		}
		
		.favorites-panel {
			background: white;
			border-radius: 12px;
			padding: 30px;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
			margin-bottom: 30px;
		}
		
		.favorites-panel h2 {
			margin-bottom: 20px;
			color: #333;
		}
		
		.favorite-list {
			display: grid;
			gap: 10px;
		}
		
		.favorite-item {
			padding: 15px;
			background: #f9f9f9;
			border-radius: 6px;
			display: flex;
			justify-content: space-between;
			align-items: center;
			border: 1px solid #e0e0e0;
		}
		
		.settings-panel {
			background: white;
			border-radius: 12px;
			padding: 30px;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
			margin-bottom: 30px;
		}
		
		.settings-panel h2 {
			margin-bottom: 20px;
			color: #333;
		}
		
		.setting-item {
			margin-bottom: 20px;
			display: grid;
			grid-template-columns: 150px 1fr;
			gap: 15px;
			align-items: center;
		}
		
		.setting-item label {
			font-weight: 500;
			color: #333;
		}
		
		.setting-item input,
		.setting-item select {
			padding: 10px;
			border: 1px solid #e0e0e0;
			border-radius: 6px;
			font-size: 14px;
		}
		
		.footer {
			text-align: center;
			color: white;
			margin-top: 40px;
			padding: 20px;
		}
		
		.progress {
			margin: 20px 0;
			padding: 15px;
			background: #f0f0f0;
			border-radius: 6px;
			display: none;
		}
		
		.progress.active {
			display: block;
		}
		
		.progress-bar {
			width: 100%;
			height: 6px;
			background: #e0e0e0;
			border-radius: 3px;
			overflow: hidden;
			margin: 10px 0;
		}
		
		.progress-fill {
			height: 100%;
			background: linear-gradient(90deg, #667eea, #764ba2);
			width: 0%;
			transition: width 0.3s;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔍 Check ProxyIP</h1>
			<p>快速检测和验证代理IP质量</p>
		</div>
		
		<!-- 主检测面板 -->
		<div class="main-panel">
			<h2>IP检测</h2>
			<div class="ip-input">
				<input type="text" id="ipInput" placeholder="输入要检测的IP或多个IP (逗号分隔)">
				<button onclick="startCheck()">开始检测</button>
			</div>
			
			<div class="progress" id="progress">
				<div id="progressText">准备中...</div>
				<div class="progress-bar">
					<div class="progress-fill" id="progressFill"></div>
				</div>
			</div>
			
			<div class="results" id="results"></div>
		</div>
		
		<!-- 收藏面板 -->
		<div class="favorites-panel">
			<h2>⭐ 我的收藏</h2>
			<div class="favorite-list" id="favoriteList">
				<p style="color: #999;">暂无收藏的IP</p>
			</div>
		</div>
		
		<!-- 设置面板 -->
		<div class="settings-panel">
			<h2>⚙️ 设置</h2>
			
			<div class="setting-item">
				<label>批量检测大小</label>
				<input type="number" id="batchSize" value="20" min="1" max="100">
			</div>
			
			<div class="setting-item">
				<label>Worker并发数</label>
				<input type="number" id="workerConcurrency" value="3" min="1" max="10">
			</div>
			
			<div class="setting-item">
				<label>检测超时(秒)</label>
				<input type="number" id="timeout" value="30" min="5" max="300">
			</div>
			
			<button onclick="saveSettings()" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer;">保存设置</button>
		</div>
		
		<div class="footer">
			<p>${beianContent}</p>
		</div>
	</div>
	
	<script>
		let favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
		let settings = {
			batchSize: parseInt(localStorage.getItem('batchSize') || '20'),
			workerConcurrency: parseInt(localStorage.getItem('workerConcurrency') || '3'),
			timeout: parseInt(localStorage.getItem('timeout') || '30')
		};
		
		// 初始化设置
		document.getElementById('batchSize').value = settings.batchSize;
		document.getElementById('workerConcurrency').value = settings.workerConcurrency;
		document.getElementById('timeout').value = settings.timeout;
		
		function saveSettings() {
			settings.batchSize = parseInt(document.getElementById('batchSize').value);
			settings.workerConcurrency = parseInt(document.getElementById('workerConcurrency').value);
			settings.timeout = parseInt(document.getElementById('timeout').value);
			
			localStorage.setItem('batchSize', settings.batchSize);
			localStorage.setItem('workerConcurrency', settings.workerConcurrency);
			localStorage.setItem('timeout', settings.timeout);
			
			alert('设置已保存');
		}
		
		function startCheck() {
			const input = document.getElementById('ipInput').value.trim();
			if (!input) {
				alert('请输入IP地址');
				return;
			}
			
			const ips = input.split(/[,\\s]+/).filter(ip => ip.length > 0);
			checkIPs(ips);
		}
		
		async function checkIPs(ips) {
			const progress = document.getElementById('progress');
			const results = document.getElementById('results');
			progress.classList.add('active');
			results.innerHTML = '';
			
			for (let i = 0; i < ips.length; i += settings.batchSize) {
				const batch = ips.slice(i, i + settings.batchSize);
				const progressText = document.getElementById('progressText');
				progressText.textContent = \`正在检测... \${i + 1} / \${ips.length}\`;
				
				try {
					const response = await fetch('/check', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({
							targets: batch,
							resolve: false,
							purity: false,
							limit: batch.length,
							concurrency: settings.workerConcurrency
						})
					});
					
					const data = await response.json();
					displayResults(data.payload?.results || [batch]);
				} catch (error) {
					console.error('检测错误:', error);
					progressText.textContent = '检测失败: ' + error.message;
				}
			}
			
			progress.classList.remove('active');
		}
		
		function displayResults(results) {
			const resultsContainer = document.getElementById('results');
			results.forEach(result => {
				const card = document.createElement('div');
				card.className = 'result-card';
				card.innerHTML = \`
					<h3>\${result.target || result.input}</h3>
					<p>状态: \${result.success ? '✅ 可用' : '❌ 不可用'}</p>
					<p>IPPure系数: \${(result.ippure || 0).toFixed(2)}</p>
					\${result.message ? \`<p>备注: \${result.message}</p>\` : ''}
					<button onclick="addFavorite('\${result.target || result.input}')" style="margin-top: 10px; padding: 8px 12px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer;">⭐ 收藏</button>
				\`;
				resultsContainer.appendChild(card);
			});
		}
		
		function addFavorite(ip) {
			if (!favorites.includes(ip)) {
				favorites.push(ip);
				localStorage.setItem('favorites', JSON.stringify(favorites));
				updateFavoritesList();
				alert('已收藏');
			} else {
				alert('已存在');
			}
		}
		
		function removeFavorite(ip) {
			favorites = favorites.filter(f => f !== ip);
			localStorage.setItem('favorites', JSON.stringify(favorites));
			updateFavoritesList();
		}
		
		function updateFavoritesList() {
			const favoriteList = document.getElementById('favoriteList');
			if (favorites.length === 0) {
				favoriteList.innerHTML = '<p style="color: #999;">暂无收藏的IP</p>';
			} else {
				favoriteList.innerHTML = favorites.map(ip => \`
					<div class="favorite-item">
						<span>\${ip}</span>
						<button onclick="removeFavorite('\${ip}')" style="padding: 5px 10px; background: #ff6b6b; color: white; border: none; border-radius: 4px; cursor: pointer;">删除</button>
					</div>
				\`).join('');
			}
		}
		
		// 页面加载时更新收藏列表
		updateFavoritesList();
	</script>
</body>
</html>`;
}

// ... (后续代码继续保持不变) ...
