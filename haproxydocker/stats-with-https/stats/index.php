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
$SOCKET_PATH = '/var/run/haproxy.sock'; // used if SOCKET_TYPE = unix
$TCP_HOST    = '127.0.0.1';                   // used if SOCKET_TYPE = tcp
$TCP_PORT    = 9999;                          // used if SOCKET_TYPE = tcp
$REFRESH_SECS = 15;

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
    $allowed = ['ready', 'drain', 'maint'];
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

$status = get_backend_status();

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
                            <?php foreach (['ready' => 'Ready', 'drain' => 'Drain', 'maint' => 'Maint'] as $stateVal => $label): ?>
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

            [['ready', 'Ready'], ['drain', 'Drain'], ['maint', 'Maint']].forEach(([stateVal, label]) => {
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

attachFormHandlers();
setInterval(refreshStatus, REFRESH_SECS * 1000);
</script>

</body>
</html>