<?php
/**
 * HAProxy Backend Status Dashboard
 * ---------------------------------
 * Reads server state via the HAProxy runtime stats socket ("show stat")
 * and lets you change a server's state (ready / drain / maint) via the
 * same socket ("set server <backend>/<server> state <state>").
 *
 * REQUIREMENTS (haproxy.cfg):
 *   global
 *       stats socket /var/run/haproxy/admin.sock mode 660 level admin
 *   -- or, for TCP instead of a unix socket --
 *       stats socket ipv4@127.0.0.1:9999 level admin
 *
 * SECURITY: This page can take servers out of rotation. Put it behind
 * HTTP basic auth / VPN / IP allowlist at the webserver level — it does
 * not implement its own authentication.
 */

session_start();

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------
$SOCKET_TYPE = 'unix';                       // 'unix' or 'tcp'
$SOCKET_PATH = '/var/run/haproxy.sock';       // used if SOCKET_TYPE = unix
$TCP_HOST    = '127.0.0.1';                   // used if SOCKET_TYPE = tcp
$TCP_PORT    = 9999;                          // used if SOCKET_TYPE = tcp
$REFRESH_SECS = 15;

// HAProxy must be configured to log to this file (in addition to, or
// instead of, stdout) for the log viewer below to work, e.g. add this
// line inside the `global` section of haproxy.cfg:
//   log /var/log/haproxy/haproxy.log local0
// and make sure /var/log/haproxy/ exists and is writable by HAProxy.
$LOG_FILE_PATH     = '/var/log/haproxy/haproxy.log';
$LOG_LINES_TO_SHOW = 200;

// ---------------------------------------------------------------------
// Efficiently read the last N lines of a (potentially large) log file
// without loading the whole thing into memory.
// ---------------------------------------------------------------------
function tail_lines(string $filepath, int $numLines = 200, int $maxBytes = 131072): array {
    if (!file_exists($filepath)) {
        return [false, "Log file not found: $filepath"];
    }
    if (!is_readable($filepath)) {
        return [false, "Log file not readable (permissions): $filepath"];
    }

    $fp = @fopen($filepath, 'r');
    if (!$fp) {
        return [false, "Could not open log file: $filepath"];
    }

    fseek($fp, 0, SEEK_END);
    $filesize = ftell($fp);
    $readSize = min($filesize, $maxBytes);
    fseek($fp, -$readSize, SEEK_END);
    $data = $readSize > 0 ? fread($fp, $readSize) : '';
    fclose($fp);

    $lines = preg_split('/\r\n|\r|\n/', $data);

    // If we didn't read from the very start of the file, the first
    // line is likely a partial line — drop it.
    if ($readSize < $filesize && count($lines) > 1) {
        array_shift($lines);
    }

    $lines = array_values(array_filter($lines, fn($l) => $l !== ''));
    $lines = array_slice($lines, -$numLines);

    return [true, $lines];
}

// ---------------------------------------------------------------------
// Low-level socket helper: send a command to the HAProxy stats socket
// and return the raw response text.
// ---------------------------------------------------------------------
function haproxy_socket_command(string $command): array {
    global $SOCKET_TYPE, $SOCKET_PATH, $TCP_HOST, $TCP_PORT;

    $errno = 0;
    $errstr = '';

    if ($SOCKET_TYPE === 'unix') {
        $address = 'unix://' . $SOCKET_PATH;
        $fp = @stream_socket_client($address, $errno, $errstr, 3);
    } else {
        $address = 'tcp://' . $TCP_HOST . ':' . $TCP_PORT;
        $fp = @stream_socket_client($address, $errno, $errstr, 3);
    }

    if (!$fp) {
        return [false, "Could not connect to HAProxy stats socket ($address): $errstr ($errno)"];
    }

    stream_set_timeout($fp, 3);
    fwrite($fp, $command . "\n");

    $response = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === false) break;
        $response .= $chunk;
    }
    fclose($fp);

    return [true, $response];
}

// ---------------------------------------------------------------------
// Fetch and parse "show stat" (CSV output) into a structured array of
// server rows, keyed by backend name.
// ---------------------------------------------------------------------
function get_backend_status(): array {
    [$ok, $raw] = haproxy_socket_command('show stat');

    if (!$ok) {
        return ['error' => $raw, 'backends' => []];
    }

    $lines = preg_split('/\r\n|\r|\n/', trim($raw));
    if (empty($lines)) {
        return ['error' => 'Empty response from HAProxy', 'backends' => []];
    }

    // First line is the header, prefixed with "# "
    $header = ltrim($lines[0], '# ');
    $columns = explode(',', $header);

    $backends = [];

    for ($i = 1; $i < count($lines); $i++) {
        $line = $lines[$i];
        if ($line === '') continue;

        $fields = explode(',', $line);
        $row = [];
        foreach ($columns as $idx => $colName) {
            $row[$colName] = $fields[$idx] ?? '';
        }

        // Skip aggregate rows — we only want individual servers,
        // not the "FRONTEND" / "BACKEND" summary lines.
        if (!isset($row['svname']) || in_array($row['svname'], ['FRONTEND', 'BACKEND'], true)) {
            continue;
        }

        $backendName = $row['pxname'] ?? 'unknown';
        $backends[$backendName][] = $row;
    }

    return ['error' => null, 'backends' => $backends];
}

// ---------------------------------------------------------------------
// Apply a state change to a specific server.
// ---------------------------------------------------------------------
function set_server_state(string $backend, string $server, string $state): array {
    $allowed = ['ready', 'drain'];
    if (!in_array($state, $allowed, true)) {
        return [false, 'Invalid state requested'];
    }

    $backend = preg_replace('/[^a-zA-Z0-9_.\-]/', '', $backend);
    $server  = preg_replace('/[^a-zA-Z0-9_.\-]/', '', $server);

    $cmd = "set server {$backend}/{$server} state {$state}";
    [$ok, $response] = haproxy_socket_command($cmd);

    return [$ok, trim($response)];
}

// ---------------------------------------------------------------------
// CSRF token (lightweight, since this is an admin action endpoint)
// ---------------------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ---------------------------------------------------------------------
// Handle POST actions (state change requests)
// ---------------------------------------------------------------------
$action_message = null;
$action_ok = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $posted_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrf_token, $posted_token)) {
        $action_message = 'Invalid CSRF token — action rejected.';
        $action_ok = false;
    } else {
        $backend = $_POST['backend'] ?? '';
        $server  = $_POST['server'] ?? '';
        $state   = $_POST['state'] ?? '';

        if ($backend && $server && $state) {
            [$ok, $resp] = set_server_state($backend, $server, $state);
            $action_ok = $ok;
            $action_message = $ok
                ? "Set {$backend}/{$server} to '{$state}'."
                : "Failed to set {$backend}/{$server}: {$resp}";
        }
    }

    // If this is an AJAX request, respond with JSON and stop.
    if (!empty($_POST['ajax'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => $action_ok, 'message' => $action_message]);
        exit;
    }
}

// If this is an AJAX poll for fresh status data, respond with JSON only.
if (isset($_GET['ajax']) && $_GET['ajax'] === 'status') {
    header('Content-Type: application/json');
    echo json_encode(get_backend_status());
    exit;
}

// If this is an AJAX poll for fresh log data, respond with JSON only.
if (isset($_GET['ajax']) && $_GET['ajax'] === 'logs') {
    header('Content-Type: application/json');
    [$ok, $result] = tail_lines($LOG_FILE_PATH, $LOG_LINES_TO_SHOW);
    echo json_encode($ok ? ['ok' => true, 'lines' => $result] : ['ok' => false, 'error' => $result]);
    exit;
}

$status = get_backend_status();
[$log_ok, $log_result] = tail_lines($LOG_FILE_PATH, $LOG_LINES_TO_SHOW);

// ---------------------------------------------------------------------
// Helper for status badge styling
// ---------------------------------------------------------------------
function status_class(string $status): string {
    $status = strtoupper($status);
    if (strpos($status, 'UP') === 0)   return 'status-up';
    if (strpos($status, 'DOWN') === 0) return 'status-down';
    if (strpos($status, 'MAINT') === 0) return 'status-maint';
    if (strpos($status, 'DRAIN') === 0) return 'status-drain';
    return 'status-unknown';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HAProxy Backend Status</title>
<style>
    * { box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #f4f5f7;
        color: #1a1a1a;
        margin: 0;
        padding: 24px;
    }
    h1 { font-size: 22px; margin-bottom: 4px; }
    .subtitle { color: #666; font-size: 13px; margin-bottom: 20px; }
    .refresh-indicator {
        display: inline-block;
        font-size: 12px;
        color: #666;
        margin-left: 8px;
    }
    .error-banner {
        background: #fdecea;
        border: 1px solid #f5c2c0;
        color: #a12622;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 16px;
        font-size: 14px;
    }
    .action-banner {
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 16px;
        font-size: 14px;
    }
    .action-ok { background: #e6f4ea; border: 1px solid #b7dfc0; color: #1e7a34; }
    .action-fail { background: #fdecea; border: 1px solid #f5c2c0; color: #a12622; }
    .backend-block {
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        margin-bottom: 20px;
        overflow: hidden;
    }
    .backend-header {
        background: #2a2f45;
        color: #fff;
        padding: 10px 16px;
        font-size: 15px;
        font-weight: 600;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
        text-align: left;
        padding: 10px 16px;
        font-size: 13px;
        border-bottom: 1px solid #eee;
    }
    th { color: #666; font-weight: 600; background: #fafafa; }
    tr:last-child td { border-bottom: none; }
    .status-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    .status-up { background: #e6f4ea; color: #1e7a34; }
    .status-down { background: #fdecea; color: #a12622; }
    .status-maint { background: #fff4e5; color: #a15c00; }
    .status-drain { background: #e8eef7; color: #2a5ea8; }
    .status-unknown { background: #eee; color: #555; }
    .actions form { display: inline-block; margin-right: 6px; }
    .btn {
        border: none;
        border-radius: 5px;
        padding: 6px 12px;
        font-size: 12px;
        cursor: pointer;
        font-weight: 600;
    }
    .btn-drain { background: #2a5ea8; color: #fff; }
    .btn-maint { background: #a15c00; color: #fff; }
    .btn-ready { background: #1e7a34; color: #fff; }
    .btn:hover { opacity: 0.85; }
    .empty-state {
        padding: 40px;
        text-align: center;
        color: #888;
    }
    .log-section {
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        margin-top: 24px;
        overflow: hidden;
    }
    .log-section summary {
        cursor: pointer;
        padding: 12px 16px;
        font-size: 15px;
        font-weight: 600;
        background: #2a2f45;
        color: #fff;
        list-style: none;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .log-section summary::-webkit-details-marker { display: none; }
    .log-section summary .arrow { transition: transform 0.15s ease; }
    .log-section[open] summary .arrow { transform: rotate(90deg); }
    .log-meta {
        font-size: 11px;
        font-weight: 400;
        color: #b7bcd6;
        margin-left: 8px;
    }
    .log-box {
        background: #12141f;
        color: #d7dae8;
        margin: 0;
        padding: 14px 16px;
        font-family: "SF Mono", Menlo, Consolas, monospace;
        font-size: 12px;
        line-height: 1.5;
        max-height: 400px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    .log-box .log-error { color: #ff8a80; }
</style>
</head>
<body>

<h1>HAProxy Backend Status
    <span class="refresh-indicator" id="refresh-indicator">auto-refreshing every <?php echo (int)$REFRESH_SECS; ?>s</span>
</h1>
<div class="subtitle">Last loaded: <?php echo date('Y-m-d H:i:s'); ?></div>

<div id="action-message">
<?php if ($action_message !== null): ?>
    <div class="action-banner <?php echo $action_ok ? 'action-ok' : 'action-fail'; ?>">
        <?php echo htmlspecialchars($action_message); ?>
    </div>
<?php endif; ?>
</div>

<div id="dashboard-content">
<?php if ($status['error']): ?>
    <div class="error-banner">Error: <?php echo htmlspecialchars($status['error']); ?></div>
<?php elseif (empty($status['backends'])): ?>
    <div class="empty-state">No backend servers found.</div>
<?php else: ?>
    <?php foreach ($status['backends'] as $backendName => $servers): ?>
        <div class="backend-block">
            <div class="backend-header"><?php echo htmlspecialchars($backendName); ?></div>
            <table>
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>Status</th>
                        <th>Weight</th>
                        <th>Check</th>
                        <th>Sessions</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($servers as $srv): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($srv['svname'] ?? ''); ?></td>
                        <td>
                            <span class="status-badge <?php echo status_class($srv['status'] ?? ''); ?>">
                                <?php echo htmlspecialchars($srv['status'] ?? 'UNKNOWN'); ?>
                            </span>
                        </td>
                        <td><?php echo htmlspecialchars($srv['weight'] ?? ''); ?></td>
                        <td><?php echo htmlspecialchars($srv['check_status'] ?? ''); ?></td>
                        <td><?php echo htmlspecialchars($srv['scur'] ?? '0'); ?></td>
                        <td class="actions">
                            <?php foreach (['ready' => 'Up', 'drain' => 'Drain'] as $stateVal => $label): ?>
                                <form method="post" class="state-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                    <input type="hidden" name="backend" value="<?php echo htmlspecialchars($backendName); ?>">
                                    <input type="hidden" name="server" value="<?php echo htmlspecialchars($srv['svname'] ?? ''); ?>">
                                    <input type="hidden" name="state" value="<?php echo $stateVal; ?>">
                                    <button type="submit" class="btn btn-<?php echo $stateVal; ?>"><?php echo $label; ?></button>
                                </form>
                            <?php endforeach; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
</div>

<details class="log-section" id="log-section">
    <summary>
        <span><span class="arrow">▶</span> Recent HAProxy Logs <span class="log-meta">(last <?php echo (int)$LOG_LINES_TO_SHOW; ?> lines, auto-refreshing)</span></span>
    </summary>
    <pre class="log-box" id="log-content"><?php
        if ($log_ok) {
            echo htmlspecialchars(implode("\n", $log_result));
        } else {
            echo '<span class="log-error">' . htmlspecialchars($log_result) . '</span>';
        }
    ?></pre>
</details>

<script>
const REFRESH_SECS = <?php echo (int)$REFRESH_SECS; ?>;
const CSRF_TOKEN = <?php echo json_encode($csrf_token); ?>;

function statusClass(status) {
    status = (status || '').toUpperCase();
    if (status.indexOf('UP') === 0) return 'status-up';
    if (status.indexOf('DOWN') === 0) return 'status-down';
    if (status.indexOf('MAINT') === 0) return 'status-maint';
    if (status.indexOf('DRAIN') === 0) return 'status-drain';
    return 'status-unknown';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : str;
    return div.innerHTML;
}

function renderDashboard(data) {
    const container = document.getElementById('dashboard-content');

    if (data.error) {
        container.innerHTML = `<div class="error-banner">Error: ${escapeHtml(data.error)}</div>`;
        return;
    }

    const backendNames = Object.keys(data.backends || {});
    if (backendNames.length === 0) {
        container.innerHTML = '<div class="empty-state">No backend servers found.</div>';
        return;
    }

    let html = '';
    backendNames.forEach(backendName => {
        const servers = data.backends[backendName];
        html += `<div class="backend-block">
            <div class="backend-header">${escapeHtml(backendName)}</div>
            <table>
                <thead>
                    <tr><th>Server</th><th>Status</th><th>Weight</th><th>Check</th><th>Sessions</th><th>Actions</th></tr>
                </thead>
                <tbody>`;

        servers.forEach(srv => {
            const svname = srv.svname || '';
            html += `<tr>
                <td>${escapeHtml(svname)}</td>
                <td><span class="status-badge ${statusClass(srv.status)}">${escapeHtml(srv.status || 'UNKNOWN')}</span></td>
                <td>${escapeHtml(srv.weight)}</td>
                <td>${escapeHtml(srv.check_status)}</td>
                <td>${escapeHtml(srv.scur || '0')}</td>
                <td class="actions">`;

            [['ready', 'Up'], ['drain', 'Drain']].forEach(([stateVal, label]) => {
                html += `<form method="post" class="state-form">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(CSRF_TOKEN)}">
                    <input type="hidden" name="backend" value="${escapeHtml(backendName)}">
                    <input type="hidden" name="server" value="${escapeHtml(svname)}">
                    <input type="hidden" name="state" value="${stateVal}">
                    <button type="submit" class="btn btn-${stateVal}">${label}</button>
                </form>`;
            });

            html += `</td></tr>`;
        });

        html += `</tbody></table></div>`;
    });

    container.innerHTML = html;
    attachFormHandlers();
}

function attachFormHandlers() {
    document.querySelectorAll('.state-form').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(form);
            formData.append('ajax', '1');

            const btn = form.querySelector('button');
            btn.disabled = true;

            try {
                const resp = await fetch(window.location.pathname, {
                    method: 'POST',
                    body: formData
                });
                const result = await resp.json();

                const msgDiv = document.getElementById('action-message');
                msgDiv.innerHTML = `<div class="action-banner ${result.ok ? 'action-ok' : 'action-fail'}">${escapeHtml(result.message)}</div>`;

                await refreshStatus();
            } catch (err) {
                const msgDiv = document.getElementById('action-message');
                msgDiv.innerHTML = `<div class="action-banner action-fail">Request failed: ${escapeHtml(err.message)}</div>`;
            } finally {
                btn.disabled = false;
            }
        });
    });
}

async function refreshStatus() {
    try {
        const resp = await fetch(window.location.pathname + '?ajax=status');
        const data = await resp.json();
        renderDashboard(data);
    } catch (err) {
        console.error('Failed to refresh status', err);
    }
}

async function refreshLogs() {
    const logBox = document.getElementById('log-content');
    if (!logBox) return;

    // Only auto-scroll if the user is already at (or near) the bottom,
    // so we don't yank their scroll position while they're reading.
    const nearBottom = (logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight) < 30;

    try {
        const resp = await fetch(window.location.pathname + '?ajax=logs');
        const data = await resp.json();

        if (data.ok) {
            logBox.textContent = (data.lines || []).join('\n');
        } else {
            logBox.innerHTML = `<span class="log-error">${escapeHtml(data.error)}</span>`;
        }

        if (nearBottom) {
            logBox.scrollTop = logBox.scrollHeight;
        }
    } catch (err) {
        console.error('Failed to refresh logs', err);
    }
}

// Scroll the log box to the bottom on initial load.
document.addEventListener('DOMContentLoaded', () => {
    const logBox = document.getElementById('log-content');
    if (logBox) logBox.scrollTop = logBox.scrollHeight;
});

attachFormHandlers();
setInterval(refreshStatus, REFRESH_SECS * 1000);
setInterval(refreshLogs, REFRESH_SECS * 1000);
</script>

</body>
</html>