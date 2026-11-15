<?php
declare(strict_types=1);
date_default_timezone_set('Asia/Dhaka');

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('X-Robots-Tag: noindex, nofollow, noarchive');

function envv(string $name, string $default = ''): string {
    $value = getenv($name);
    return $value === false ? $default : trim((string)$value);
}
function secret_pepper(): string {
    return envv('PB_KEY_PEPPER', envv('PB_LICENSE_PEPPER'));
}
function config_ready(): bool {
    return envv('PB_FIREBASE_DATABASE_URL') !== ''
        && envv('PB_FIREBASE_SERVICE_ACCOUNT_JSON') !== ''
        && secret_pepper() !== ''
        && envv('PB_ADMIN_PASSWORD') !== '';
}
function json_out(int $status, array $data): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
    exit;
}
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function u_substr(string $value, int $start, int $length): string {
    if (function_exists('mb_substr')) return mb_substr($value, $start, $length, 'UTF-8');
    if (preg_match_all('/./us', $value, $chars)) return implode('', array_slice($chars[0], $start, $length));
    return substr($value, $start, $length);
}
function u_lower(string $value): string { return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value); }
function base64url(string $data): string { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function current_route(): string {
    $path = (string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/');
    if (preg_match('#^/api/([a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*)/?$#', $path, $m)) return 'api/' . strtolower($m[1]);
    if (preg_match('#^/apikey=([^/]+)$#', $path, $m)) {
        $part = []; parse_str('apikey=' . $m[1], $part); $_GET = array_merge($_GET, $part); return 'api/verify';
    }
    if ($path === '/' && strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'GET'
        && isset($_GET['apikey']) && (isset($_GET['txnid']) || isset($_GET['txn_id']))) return 'api/verify';
    if ($path === '/admin' || $path === '/admin/') return 'admin';
    if ($path === '/healthz' || $path === '/healthz/') return 'healthz';
    if ($path === '/health' || $path === '/health/') return 'api/health';
    return '';
}
function service_account(): array {
    $sa = json_decode(envv('PB_FIREBASE_SERVICE_ACCOUNT_JSON'), true);
    if (!is_array($sa) || empty($sa['client_email']) || empty($sa['private_key']) || empty($sa['token_uri'])) {
        throw new RuntimeException('Firebase service account configuration is invalid.');
    }
    $sa['private_key'] = str_replace('\\n', "\n", (string)$sa['private_key']);
    return $sa;
}
function firebase_token(): string {
    static $token = '';
    static $expiry = 0;
    if ($token !== '' && $expiry > time() + 90) return $token;
    $sa = service_account();
    $cacheFile = sys_get_temp_dir() . '/pb_oauth_' . preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($sa['project_id'] ?? 'project')) . '.json';
    if (is_file($cacheFile)) {
        $cached = json_decode((string)@file_get_contents($cacheFile), true);
        if (is_array($cached) && !empty($cached['access_token']) && (int)($cached['expires_at'] ?? 0) > time() + 90) {
            $token = (string)$cached['access_token']; $expiry = (int)$cached['expires_at']; return $token;
        }
    }
    $now = time();
    $head = base64url(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $claim = base64url(json_encode([
        'iss' => $sa['client_email'],
        'scope' => 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/firebase.database',
        'aud' => $sa['token_uri'], 'iat' => $now, 'exp' => $now + 3500
    ]));
    $unsigned = $head . '.' . $claim;
    $private = openssl_pkey_get_private($sa['private_key']);
    if ($private === false) throw new RuntimeException('Firebase private key cannot be loaded.');
    $sig = '';
    if (!openssl_sign($unsigned, $sig, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Firebase OAuth signing failed.');
    $ch = curl_init((string)$sa['token_uri']);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $unsigned . '.' . base64url($sig)]),
        CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2
    ]);
    $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
    $data = json_decode((string)$body, true);
    if ($code < 200 || $code >= 300 || !is_array($data) || empty($data['access_token'])) {
        throw new RuntimeException('Firebase server authentication failed (HTTP ' . $code . '). ' . $err);
    }
    $token = (string)$data['access_token']; $expiry = $now + (int)($data['expires_in'] ?? 3500);
    @file_put_contents($cacheFile, json_encode(['access_token' => $token, 'expires_at' => $expiry]), LOCK_EX);
    @chmod($cacheFile, 0600);
    return $token;
}
function fb_request(string $method, string $path, $payload = null, array $extraHeaders = [], array $query = [], float $timeoutSeconds = 12.0): array {
    $base = rtrim(envv('PB_FIREBASE_DATABASE_URL'), '/');
    $segments = array_map('rawurlencode', array_filter(explode('/', trim($path, '/')), 'strlen'));
    $url = $base . '/' . implode('/', $segments) . '.json';
    if ($query) $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    $headers = array_merge(['Authorization: Bearer ' . firebase_token(), 'Accept: application/json'], $extraHeaders);
    if ($payload !== null) $headers[] = 'Content-Type: application/json';
    $responseHeaders = [];
    $ch = curl_init($url);
    $timeoutMs = max(150, min(12000, (int)ceil($timeoutSeconds * 1000)));
    $connectTimeoutMs = min(2500, $timeoutMs);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT_MS => $connectTimeoutMs, CURLOPT_TIMEOUT_MS => $timeoutMs, CURLOPT_NOSIGNAL => true,
        CURLOPT_HTTPHEADER => $headers, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HEADERFUNCTION => function ($curl, $line) use (&$responseHeaders) {
            $len = strlen($line); $parts = explode(':', $line, 2);
            if (count($parts) === 2) $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
            return $len;
        }
    ]);
    if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
    $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $error = curl_error($ch); curl_close($ch);
    if ($body === false) throw new RuntimeException('Firebase network error: ' . $error);
    return ['code' => $code, 'body' => (string)$body, 'json' => json_decode((string)$body, true), 'headers' => $responseHeaders];
}
function fb_get(string $path): array {
    $r = fb_request('GET', $path);
    if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Firebase read failed at ' . $path . ' (HTTP ' . $r['code'] . ').');
    return is_array($r['json']) ? $r['json'] : [];
}
function fb_query(string $path, array $query): array {
    $r = fb_request('GET', $path, null, [], $query);
    if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Firebase query failed (HTTP ' . $r['code'] . ').');
    return is_array($r['json']) ? $r['json'] : [];
}
function fb_write(string $method, string $path, array $data): void {
    $r = fb_request($method, $path, $data);
    if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Firebase write failed at ' . $path . ' (HTTP ' . $r['code'] . ').');
}
function fb_delete(string $path): void {
    $r = fb_request('DELETE', $path);
    if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Firebase delete failed (HTTP ' . $r['code'] . ').');
}
function fb_create_only(string $path, array $data): bool {
    $read = fb_request('GET', $path, null, ['X-Firebase-ETag: true']);
    if ($read['code'] < 200 || $read['code'] >= 300) throw new RuntimeException('Firebase duplicate lookup failed (HTTP ' . $read['code'] . ').');
    if (trim($read['body']) !== '' && trim($read['body']) !== 'null') return false;
    $etag = (string)($read['headers']['etag'] ?? '');
    if ($etag === '') throw new RuntimeException('Firebase did not provide an ETag.');
    $write = fb_request('PUT', $path, $data, ['If-Match: ' . $etag]);
    if ($write['code'] === 412) return false;
    if ($write['code'] < 200 || $write['code'] >= 300) throw new RuntimeException('Firebase atomic create failed (HTTP ' . $write['code'] . ').');
    return true;
}
function fb_atomic_add(string $path, array $delta, int $retries = 8, float $timeoutSeconds = 12.0): void {
    for ($i = 0; $i < $retries; $i++) {
        $r = fb_request('GET', $path, null, ['X-Firebase-ETag: true'], [], $timeoutSeconds);
        if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Firebase aggregate read failed.');
        $current = is_array($r['json']) ? $r['json'] : [];
        foreach ($delta as $field => $value) $current[$field] = (float)($current[$field] ?? 0) + (float)$value;
        $etag = (string)($r['headers']['etag'] ?? '');
        if ($etag === '') throw new RuntimeException('Firebase aggregate ETag missing.');
        $w = fb_request('PUT', $path, $current, ['If-Match: ' . $etag], [], $timeoutSeconds);
        if ($w['code'] >= 200 && $w['code'] < 300) return;
        if ($w['code'] !== 412) throw new RuntimeException('Firebase aggregate write failed (HTTP ' . $w['code'] . ').');
        usleep(20000 * ($i + 1));
    }
    throw new RuntimeException('Firebase aggregate contention; retry later.');
}
function add_sharded_totals(string $root, array $delta, float $timeoutSeconds = 12.0): void {
    $shard = sprintf('%02d', random_int(0, 31));
    fb_atomic_add($root . '/shards/' . $shard, $delta, 2, $timeoutSeconds);
}
function key_hash(string $key): string { return hash_hmac('sha256', strtoupper(trim($key)), secret_pepper()); }
function encrypt_admin_key(string $plain): array {
    $encKey = hash('sha256', 'payment-bridge-admin-key-reveal|' . secret_pepper(), true);
    $iv = random_bytes(12); $tag = '';
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) throw new RuntimeException('Could not encrypt the new key for Admin copy access.');
    return ['secret_cipher' => base64_encode($cipher), 'secret_iv' => base64_encode($iv), 'secret_tag' => base64_encode($tag), 'secret_version' => 1];
}
function decrypt_admin_key(array $record): string {
    if (empty($record['secret_cipher']) || empty($record['secret_iv']) || empty($record['secret_tag'])) return '';
    $cipher = base64_decode((string)$record['secret_cipher'], true);
    $iv = base64_decode((string)$record['secret_iv'], true);
    $tag = base64_decode((string)$record['secret_tag'], true);
    if ($cipher === false || $iv === false || $tag === false || strlen($iv) !== 12 || strlen($tag) !== 16) return '';
    $encKey = hash('sha256', 'payment-bridge-admin-key-reveal|' . secret_pepper(), true);
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $iv, $tag);
    return is_string($plain) ? $plain : '';
}
function request_json(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 120000) json_out(413, ['ok' => false, 'message' => 'Request too large.']);
    $value = json_decode($raw, true);
    if (!is_array($value)) return $_POST;
    return $value;
}
function header_value(string $name): string {
    return trim((string)($_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $name))] ?? ''));
}
function app_key_record(string $rawKey): array {
    if ($rawKey === '' || strlen($rawKey) < 24 || strlen($rawKey) > 256) json_out(401, ['ok' => false, 'message' => 'App upload key is required.']);
    $hash = key_hash($rawKey);
    $record = fb_get('settings/app_upload_keys/' . $hash);
    if (empty($record['active'])) json_out(401, ['ok' => false, 'message' => 'App upload key is invalid or revoked.']);
    return ['hash' => $hash, 'record' => $record];
}
function verification_key_record(string $rawKey): array {
    if ($rawKey === '' || strlen($rawKey) < 24 || strlen($rawKey) > 256) json_out(401, ['status' => false, 'result' => 'unauthorized', 'message' => 'API key is required.']);
    $hash = key_hash($rawKey);
    $record = fb_get('settings/verification_api_keys/' . $hash);
    if (empty($record['active'])) json_out(401, ['status' => false, 'result' => 'unauthorized', 'message' => 'API key is invalid or revoked.']);
    return ['hash' => $hash, 'record' => $record];
}
function verification_rate_limit(string $keyHash, int $requestedLimit = 0): array {
    $defaultLimit = max(10, min(300, (int)envv('PB_VERIFY_RATE_LIMIT_PER_MIN', '120')));
    $limit = $requestedLimit > 0 ? max(10, min(300, $requestedLimit)) : $defaultLimit;
    $now = microtime(true);
    $file = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'pb_verify_rl_' . substr($keyHash, 0, 32) . '.json';
    $fp = @fopen($file, 'c+');
    if (!$fp) return ['allowed' => true, 'limit' => $limit, 'remaining' => $limit, 'retry_after' => 0];
    if (!@flock($fp, LOCK_EX)) { fclose($fp); return ['allowed' => true, 'limit' => $limit, 'remaining' => $limit, 'retry_after' => 0]; }
    $raw = stream_get_contents($fp);
    $state = json_decode(is_string($raw) ? $raw : '', true);
    $events = is_array($state['events'] ?? null) ? $state['events'] : [];
    $events = array_values(array_filter($events, static function ($ts) use ($now) { return is_numeric($ts) && (float)$ts > $now - 60.0; }));
    $allowed = count($events) < $limit;
    if ($allowed) $events[] = $now;
    $retryAfter = 0;
    if (!$allowed && isset($events[0])) $retryAfter = max(1, (int)ceil(60.0 - ($now - (float)$events[0])));
    rewind($fp); ftruncate($fp, 0); fwrite($fp, json_encode(['events' => $events], JSON_UNESCAPED_SLASHES)); fflush($fp);
    flock($fp, LOCK_UN); fclose($fp);
    return ['allowed' => $allowed, 'limit' => $limit, 'remaining' => max(0, $limit - count($events)), 'retry_after' => $retryAfter];
}
function valid_device_id(string $id): bool { return preg_match('/^[A-Za-z0-9_-]{8,80}$/', $id) === 1; }
function authenticate_app(array $body): array {
    $key = header_value('X-App-Key');
    if ($key === '') $key = (string)($body['app_key'] ?? '');
    $app = app_key_record($key);
    $deviceId = trim((string)($body['device_id'] ?? ''));
    if (!valid_device_id($deviceId)) json_out(422, ['ok' => false, 'message' => 'Invalid installation ID.']);
    $device = fb_get('devices/' . $deviceId);
    if (!empty($device['blocked'])) json_out(403, ['ok' => false, 'message' => 'This installation is disabled by administrator.']);
    return ['key' => $app, 'device_id' => $deviceId, 'device' => $device];
}
function update_device_seen(string $deviceId, array $body, string $keyHash, string $state = 'active'): void {
    $path = 'devices/' . $deviceId;
    $old = fb_get($path);
    $now = time();
    $record = [
        'device_id' => $deviceId,
        'label' => u_substr(trim((string)($body['device_label'] ?? ($old['label'] ?? ''))), 0, 80),
        'model' => u_substr(trim((string)($body['model'] ?? ($old['model'] ?? 'Unknown'))), 0, 100),
        'app_version' => u_substr(trim((string)($body['app_version'] ?? ($old['app_version'] ?? ''))), 0, 32),
        'app_key_hash' => $keyHash,
        'active' => true,
        'blocked' => false,
        'connection_state' => $state,
        'permission_sms' => !empty($body['permission_sms']),
        'permission_notifications' => !empty($body['permission_notifications']),
        'permission_battery_exempt' => !empty($body['permission_battery_exempt']),
        'background_restricted' => !empty($body['background_restricted']),
        'network_connected' => !empty($body['network_connected']),
        'pending_queue_count' => max(0, min(5000, (int)($body['pending_queue_count'] ?? ($old['pending_queue_count'] ?? 0)))),
        'android_sdk' => max(0, min(100, (int)($body['android_sdk'] ?? 0))),
        'first_seen' => (int)($old['first_seen'] ?? $now),
        'last_seen' => $now,
        'last_login_at' => $state === 'logged_in' ? $now : (int)($old['last_login_at'] ?? 0),
        'last_connect_at' => ($state === 'active' && (string)($old['connection_state'] ?? '') !== 'active') ? $now : (int)($old['last_connect_at'] ?? 0),
        'last_heartbeat_at' => $state === 'active' ? $now : (int)($old['last_heartbeat_at'] ?? 0)
    ];
    fb_write('PATCH', $path, $record);
}
function api_app_validate(array $body): void {
    $auth = authenticate_app($body);
    update_device_seen($auth['device_id'], $body, $auth['key']['hash'], 'logged_in');
    json_out(200, ['ok' => true, 'status' => 'active', 'device_id' => $auth['device_id'], 'message' => 'App key accepted. This key can be used on multiple devices.']);
}
function api_heartbeat(array $body): void {
    $auth = authenticate_app($body);
    update_device_seen($auth['device_id'], $body, $auth['key']['hash'], 'active');
    json_out(200, ['ok' => true, 'status' => 'active', 'server_time' => time()]);
}
function api_disconnect(array $body): void {
    $auth = authenticate_app($body);
    fb_write('PATCH', 'devices/' . $auth['device_id'], ['last_seen' => time(), 'last_disconnect_at' => time(), 'connection_state' => 'disconnected']);
    json_out(200, ['ok' => true, 'status' => 'disconnected']);
}
function lookup_attempt_path(string $txnId): string {
    return 'verification_lookup_attempts/' . hash('sha256', strtoupper(trim($txnId)));
}
function add_lookup_attempt(string $txnId, int $retries = 2, float $timeoutSeconds = 0.8): void {
    $path = lookup_attempt_path($txnId);
    for ($i = 0; $i < max(1, min(3, $retries)); $i++) {
        $r = fb_request('GET', $path, null, ['X-Firebase-ETag: true'], [], $timeoutSeconds);
        if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Could not read verification attempt counter.');
        $current = is_array($r['json']) ? $r['json'] : [];
        $current['attempt_count'] = (int)($current['attempt_count'] ?? 0) + 1;
        $current['last_attempt_at'] = time();
        $etag = (string)($r['headers']['etag'] ?? '');
        if ($etag === '') throw new RuntimeException('Verification attempt counter ETag missing.');
        $w = fb_request('PUT', $path, $current, ['If-Match: ' . $etag], [], $timeoutSeconds);
        if ($w['code'] >= 200 && $w['code'] < 300) return;
        if ($w['code'] !== 412) throw new RuntimeException('Could not save verification attempt counter.');
        usleep(15000 * ($i + 1));
    }
    throw new RuntimeException('Verification attempt counter busy.');
}
function parse_month_ms(array $item): string {
    $ms = (int)($item['transaction_at_ms'] ?? 0);
    if ($ms <= 0) $ms = (int)($item['received_at_ms'] ?? 0);
    $ts = $ms > 0 ? (int)floor($ms / 1000) : time();
    return date('Y-m', $ts);
}
function api_ingest(array $body): void {
    $auth = authenticate_app($body);
    $item = $body['item'] ?? null;
    if (!is_array($item)) json_out(422, ['ok' => false, 'message' => 'Payment item is missing.']);
    $smsKey = strtolower(trim((string)($item['sms_key'] ?? '')));
    $method = strtolower(trim((string)($item['method'] ?? '')));
    $txnId = strtoupper(trim((string)($item['txn_id'] ?? '')));
    $amount = (float)($item['amount'] ?? 0);
    if (!preg_match('/^[a-f0-9]{32,64}$/', $smsKey)) json_out(422, ['ok' => false, 'message' => 'Invalid SMS idempotency key.']);
    if (!in_array($method, ['bkash', 'nagad', 'rocket'], true)) json_out(422, ['ok' => false, 'message' => 'Unsupported payment method.']);
    if ($amount < 0 || $amount > 100000000) json_out(422, ['ok' => false, 'message' => 'Invalid amount.']);
    if ($txnId !== '' && !preg_match('/^[A-Z0-9_-]{4,100}$/', $txnId)) json_out(422, ['ok' => false, 'message' => 'Invalid transaction id.']);
    $counterparty = trim((string)($item['counterparty_number'] ?? $item['sender'] ?? ''));
    $receivedMs = (int)($item['received_at_ms'] ?? 0);
    if ($receivedMs <= 0) $receivedMs = (int)(microtime(true) * 1000);
    $transactionMs = (int)($item['transaction_at_ms'] ?? 0);
    $eventMs = $transactionMs > 0 ? $transactionMs : $receivedMs;
    $createdAt = (int)floor($eventMs / 1000);
    $storedAt = time();
    $deviceId = $auth['device_id'];
    $month = parse_month_ms($item);
    $day = date('Y-m-d', $createdAt);
    $simSlot = trim((string)($item['sim_slot'] ?? 'unknown'));
    $simLabel = u_substr(trim((string)($item['sim_label'] ?? '')), 0, 80);
    $simNumber = normalize_number((string)($item['sim_number'] ?? ''));
    $simCarrier = u_substr(trim((string)($item['sim_carrier'] ?? '')), 0, 80);
    $simIdentity = $simNumber !== '' ? 'number:' . $simNumber : ('device:' . $deviceId . '|slot:' . $simSlot . '|carrier:' . u_lower($simCarrier));
    $simKey = hash('sha256', $simIdentity);
    if ($simLabel === '') $simLabel = $simCarrier !== '' ? $simCarrier . ' · ' . ($simSlot === 'unknown' ? 'SIM' : 'SIM ' . $simSlot) : ($simSlot === 'unknown' ? 'SIM unknown' : 'SIM ' . $simSlot);
    $lookupAttempts = $txnId !== '' ? fb_get(lookup_attempt_path($txnId)) : [];
    $priorVerifyAttempts = (int)($lookupAttempts['attempt_count'] ?? 0);
    $record = [
        'amount' => $amount,
        'sender' => $counterparty,
        'txn_id' => $txnId,
        'method' => $method,
        'payment_medium' => (string)($item['payment_medium'] ?? $method),
        'transaction_type' => (string)($item['transaction_type'] ?? 'other_payment'),
        'transaction_type_source' => (string)($item['transaction_type_source'] ?? 'sms_keyword_rule'),
        'direction' => (string)($item['direction'] ?? 'unknown'),
        'counterparty_role' => (string)($item['counterparty_role'] ?? ''),
        'parse_status' => (string)($item['parse_status'] ?? 'complete'),
        'reference' => (string)($item['reference'] ?? ''),
        'fee_amount' => (float)($item['fee_amount'] ?? 0),
        'balance' => (float)($item['balance'] ?? 0),
        'sms_sender' => u_substr((string)($item['sms_sender'] ?? ''), 0, 120),
        'counterparty_name' => u_substr((string)($item['counterparty_name'] ?? ''), 0, 120),
        'message' => u_substr((string)($item['message'] ?? ''), 0, 3000),
        'transaction_at' => (string)($item['transaction_at'] ?? ''),
        'transaction_at_ms' => $transactionMs,
        'received_at' => (string)($item['received_at'] ?? date('Y-m-d H:i:s', (int)floor($receivedMs / 1000))),
        'received_at_ms' => $receivedMs,
        'created_at' => $createdAt,
        'day' => $day,
        'sim_key' => $simKey,
        'sim_slot' => $simSlot,
        'sim_label' => $simLabel,
        'sim_number' => $simNumber,
        'sim_carrier' => $simCarrier,
        'sim_subscription_id' => (int)($item['sim_subscription_id'] ?? -1),
        'stored_at' => $storedAt,
        'currency' => 'BDT',
        'status' => 'unused',
        'verify_attempt_count' => $priorVerifyAttempts,
        'last_verify_attempt_at' => (int)($lookupAttempts['last_attempt_at'] ?? 0),
        'device_id' => $auth['device_id']
    ];
    $smsSaved = fb_create_only('sms_messages/' . $smsKey, $record);
    if ($smsSaved) {
        try { add_sharded_totals('reports/monthly/' . $month, ['sms_count' => 1], 1.0); } catch (Throwable $ignored) {}
        try { add_sharded_totals('reports/daily/' . $day, ['sms_count' => 1], 1.0); } catch (Throwable $ignored) {}
    }
    $txnSaved = false; $txnDuplicate = false; $txnKey = '';
    if ($txnId !== '' && $amount > 0) {
        $txnKey = hash('sha256', $method . '|' . $txnId);
        $record['sms_id'] = $smsKey;
        $record['month'] = $month;
        $txnSaved = fb_create_only('payment_transactions/' . $txnKey, $record);
        $txnDuplicate = false;
        if (!$txnSaved) {
            $existing = fb_get('payment_transactions/' . $txnKey);
            $sameSmsRetry = (string)($existing['sms_id'] ?? '') === $smsKey;
            $txnDuplicate = !$sameSmsRetry;
            if ($txnDuplicate) {
                $duplicateEventKey = hash('sha256', $method . '|' . $txnId . '|' . $smsKey);
                $duplicateEvent = [
                    'method' => $method, 'txn_id' => $txnId, 'amount' => $amount,
                    'sms_id' => $smsKey, 'device_id' => $deviceId,
                    'created_at' => $createdAt, 'stored_at' => $storedAt
                ];
                try {
                    if (fb_create_only('duplicate_events/' . $duplicateEventKey, $duplicateEvent)) {
                        add_sharded_totals('reports/monthly/' . $month, ['duplicate_txn_count' => 1]);
                        add_sharded_totals('reports/daily/' . $day, ['duplicate_txn_count' => 1]);
                    }
                } catch (Throwable $ignored) {}
            }
        }
        if ($txnSaved) {
            $direction = strtolower((string)$record['direction']);
            $totals = ['payment_count' => 1];
            $simPrefix = 'sim_' . substr($simKey, 0, 24) . '_';
            $totals[$simPrefix . 'payment_count'] = 1;
            if ($direction === 'credit') {
                $totals['incoming_count'] = 1; $totals['incoming_amount'] = $amount;
                $totals[$simPrefix . 'incoming_count'] = 1; $totals[$simPrefix . 'incoming_amount'] = $amount;
            } elseif ($direction === 'debit') {
                $totals['outgoing_count'] = 1; $totals['outgoing_amount'] = $amount;
                $totals[$simPrefix . 'outgoing_count'] = 1; $totals[$simPrefix . 'outgoing_amount'] = $amount;
            }
            try { add_sharded_totals('reports/monthly/' . $month, $totals); } catch (Throwable $ignored) {}
            try { add_sharded_totals('reports/daily/' . $day, $totals); } catch (Throwable $ignored) {}
            try {
                fb_create_only('reports/sim_registry/' . $simKey, [
                    'sim_key' => $simKey, 'label' => $simLabel, 'number' => $simNumber,
                    'carrier' => $simCarrier, 'slot' => $simSlot, 'device_id' => $deviceId,
                    'created_at' => $storedAt
                ]);
            } catch (Throwable $ignored) {}
        }
        try { fb_write('PATCH', 'payment_txn_index/' . hash('sha256', $txnId), [$method => $txnKey]); } catch (Throwable $ignored) {}
    }
    update_device_seen($deviceId, $body, $auth['key']['hash'], 'active');
    json_out(200, ['ok' => true, 'sms_saved' => $smsSaved, 'transaction_saved' => $txnSaved, 'duplicate_transaction' => $txnDuplicate, 'transaction_key' => $txnKey, 'message' => $txnDuplicate ? 'SMS stored; transaction already exists.' : 'Payment SMS accepted.']);
}
function normalize_number(string $value): string {
    $digits = preg_replace('/\D+/', '', $value) ?? '';
    if (strpos($digits, '880') === 0 && strlen($digits) >= 13) $digits = '0' . substr($digits, 3);
    return $digits;
}
function add_api_metric(string $result): void {
    $month = date('Y-m'); $day = date('Y-m-d');
    $delta = ['requests' => 1];
    $field = 'result_' . preg_replace('/[^a-z_]/', '', $result);
    $delta[$field] = 1;
    try { add_sharded_totals('metrics/api_monthly/' . $month, $delta, 1.0); } catch (Throwable $ignored) {}
    try { add_sharded_totals('metrics/api_daily/' . $day, $delta, 1.0); } catch (Throwable $ignored) {}
}
function verify_response(bool $ok, string $result, string $message, ?array $record = null, array $extra = []): void {
    add_api_metric($result);
    $out = ['status' => $ok, 'result' => $result, 'message' => $message];
    if ($record !== null) {
        $out = array_merge($out, [
            'amount' => isset($record['amount']) ? (float)$record['amount'] : null,
            'sender' => (string)($record['sender'] ?? ''),
            'sender_role' => (string)($record['counterparty_role'] ?? ''),
            'counterparty_name' => (string)($record['counterparty_name'] ?? ''),
            'txn_id' => (string)($record['txn_id'] ?? ''),
            'method' => (string)($record['method'] ?? ''),
            'payment_medium' => (string)($record['payment_medium'] ?? ($record['method'] ?? '')),
            'transaction_type' => (string)($record['transaction_type'] ?? ''),
            'transaction_type_source' => (string)($record['transaction_type_source'] ?? ''),
            'direction' => (string)($record['direction'] ?? 'unknown'),
            'sms_sender' => (string)($record['sms_sender'] ?? ''),
            'reference' => (string)($record['reference'] ?? ''),
            'fee_amount' => isset($record['fee_amount']) ? (float)$record['fee_amount'] : null,
            'balance' => isset($record['balance']) ? (float)$record['balance'] : null,
            'currency' => (string)($record['currency'] ?? 'BDT'),
            'transaction_at' => (string)($record['transaction_at'] ?? ''),
            'received_at' => (string)($record['received_at'] ?? ''),
            'sim_slot' => (string)($record['sim_slot'] ?? 'unknown'),
            'sim_label' => (string)($record['sim_label'] ?? ''),
            'sim_number' => (string)($record['sim_number'] ?? ''),
            'sim_carrier' => (string)($record['sim_carrier'] ?? ''),
            'sim_subscription_id' => (int)($record['sim_subscription_id'] ?? -1),
            'payment_status' => (string)($record['status'] ?? 'unused'),
            'transaction_status' => (string)($record['status'] ?? 'unused')
        ]);
    }
    json_out(200, array_merge($out, $extra));
}
function update_verify_attempt(string $path): array {
    for ($i = 0; $i < 5; $i++) {
        $r = fb_request('GET', $path, null, ['X-Firebase-ETag: true']);
        if ($r['code'] < 200 || $r['code'] >= 300 || !is_array($r['json'])) throw new RuntimeException('Could not update transaction verification state.');
        $record = $r['json'];
        if (in_array(strtolower((string)($record['status'] ?? '')), ['used','success','verified','refunded'], true)) return $record;
        $record['verify_attempt_count'] = (int)($record['verify_attempt_count'] ?? 0) + 1;
        $record['last_verify_attempt_at'] = time();
        $etag = (string)($r['headers']['etag'] ?? '');
        $w = fb_request('PUT', $path, $record, ['If-Match: ' . $etag]);
        if ($w['code'] >= 200 && $w['code'] < 300) return $record;
        if ($w['code'] !== 412) throw new RuntimeException('Could not save verification attempt.');
    }
    throw new RuntimeException('Verification update busy.');
}
function query_candidate(string $method, string $txnId, float $timeoutSeconds = 3.0): ?array {
    $key = hash('sha256', $method . '|' . $txnId);
    $path = 'payment_transactions/' . $key;
    $r = fb_request('GET', $path, null, ['X-Firebase-ETag: true'], [], $timeoutSeconds);
    if ($r['code'] < 200 || $r['code'] >= 300) throw new RuntimeException('Payment lookup failed (HTTP ' . $r['code'] . ').');
    if (!is_array($r['json'])) return null;
    return ['path' => $path, 'key' => $key, 'record' => $r['json'], 'etag' => (string)($r['headers']['etag'] ?? '')];
}
function query_candidates_for_txn(string $txnId, float $timeoutSeconds, bool $allowLegacyFallback = true): array {
    $endAt = microtime(true) + max(0.2, $timeoutSeconds);
    $indexPath = 'payment_txn_index/' . hash('sha256', $txnId);
    $remaining = max(0.2, $endAt - microtime(true));
    $index = fb_request('GET', $indexPath, null, [], [], min(1.0, $remaining));
    if ($index['code'] < 200 || $index['code'] >= 300) throw new RuntimeException('Transaction index lookup failed (HTTP ' . $index['code'] . ').');
    $indexMap = is_array($index['json']) ? $index['json'] : [];
    $candidateKeys = [];
    foreach ($indexMap as $method => $key) {
        $cleanMethod = strtolower((string)$method);
        $cleanKey = strtolower(preg_replace('/[^a-f0-9]/', '', (string)$key));
        if (in_array($cleanMethod, ['bkash','nagad','rocket'], true) && strlen($cleanKey) === 64) $candidateKeys[$cleanMethod] = $cleanKey;
    }
    $candidates = [];
    if ($candidateKeys) {
        foreach ($candidateKeys as $method => $key) {
            $remaining = $endAt - microtime(true);
            if ($remaining <= 0.15) break;
            $path = 'payment_transactions/' . $key;
            $r = fb_request('GET', $path, null, ['X-Firebase-ETag: true'], [], min(1.5, max(0.2, $remaining)));
            if ($r['code'] >= 200 && $r['code'] < 300 && is_array($r['json'])) {
                $candidates[] = ['path'=>$path, 'key'=>$key, 'record'=>$r['json'], 'etag'=>(string)($r['headers']['etag'] ?? '')];
            }
        }
        return $candidates;
    }
    // Backward-compatible fallback runs once per request only. Repeating three legacy
    // lookups on every poll would overload Firebase when many callers wait for a new SMS.
    if (!$allowLegacyFallback) return [];
    $methods = ['bkash','nagad','rocket'];
    foreach ($methods as $method) {
        $remaining = $endAt - microtime(true);
        if ($remaining <= 0.15) break;
        $perCall = max(0.2, min(0.8, $remaining / max(1, count($methods))));
        $candidate = query_candidate($method, $txnId, $perCall);
        if ($candidate !== null) $candidates[] = $candidate;
    }
    return $candidates;
}
function api_verify(array $input): void {
    $apiKey = trim(header_value('X-API-Key'));
    if ($apiKey === '') $apiKey = trim((string)($input['apikey'] ?? ''));
    $key = verification_key_record($apiKey);
    $keyRecord = is_array($key['record'] ?? null) ? $key['record'] : [];
    $rate = verification_rate_limit((string)$key['hash'], (int)($keyRecord['rate_limit_per_min'] ?? 0));
    if (empty($rate['allowed'])) {
        header('Retry-After: ' . max(1, (int)$rate['retry_after']));
        header('X-RateLimit-Limit: ' . (int)$rate['limit']);
        header('X-RateLimit-Remaining: 0');
        json_out(429, ['status'=>false, 'result'=>'rate_limited', 'message'=>'Verification API rate limit reached. Retry after the indicated time.', 'limit_per_minute'=>$rate['limit'], 'remaining'=>0, 'retry_after_seconds'=>$rate['retry_after']]);
    }
    header('X-RateLimit-Limit: ' . (int)$rate['limit']);
    header('X-RateLimit-Remaining: ' . (int)$rate['remaining']);
    $settings = array_merge([
        'verify_number' => false, 'verify_amount' => true, 'verify_txn_id' => true,
        'verify_method' => true, 'wait_seconds' => 10, 'poll_interval_ms' => 1000
    ], fb_get('settings/verification'));
    $settings['wait_seconds'] = max(0, min(60, (int)($keyRecord['wait_seconds'] ?? $settings['wait_seconds'])));
    $settings['poll_interval_ms'] = max(250, min(5000, (int)($keyRecord['poll_interval_ms'] ?? $settings['poll_interval_ms'])));
    $checks = [
        'number' => !empty($settings['verify_number']),
        'amount' => !empty($settings['verify_amount']),
        'txn_id' => !empty($settings['verify_txn_id']),
        'method' => !empty($settings['verify_method'])
    ];
    if (!in_array(true, $checks, true)) json_out(422, ['status'=>false, 'result'=>'invalid_rules', 'message'=>'Enable at least one verification rule. Transaction ID lookup is always required.']);
    $txnId = strtoupper(trim((string)($input['txnid'] ?? $input['txn_id'] ?? '')));
    $method = strtolower(trim((string)($input['method'] ?? '')));
    $number = normalize_number((string)($input['number'] ?? ''));
    $amountRaw = $input['amount'] ?? $input['ammount'] ?? null;
    $amountPresent = $amountRaw !== null && is_numeric($amountRaw);
    $amount = $amountPresent ? (float)$amountRaw : null;
    if ($txnId === '' || strlen($txnId) > 100 || !preg_match('/^[A-Z0-9_-]+$/', $txnId)) json_out(422, ['status' => false, 'result' => 'invalid_request', 'message' => 'A valid txnid is required for lookup.']);
    if ($amountPresent && ($amount < 0 || $amount > 100000000)) json_out(422, ['status' => false, 'result' => 'invalid_request', 'message' => 'Invalid amount.']);
    if ($checks['method'] && !in_array($method, ['bkash', 'nagad', 'rocket'], true)) json_out(422, ['status' => false, 'result' => 'invalid_request', 'message' => 'A valid method is required.']);
    $missing = [];
    if ($checks['number'] && $number === '') $missing[] = 'number';
    if ($checks['amount'] && !$amountPresent) $missing[] = 'amount';
    if ($checks['method'] && $method === '') $missing[] = 'method';
    if ($missing) verify_response(false, 'invalid_request', 'Required verification values are missing.', null, ['missing' => $missing]);

    $wait = max(0, min(60, (int)$settings['wait_seconds']));
    $poll = max(250, min(5000, (int)$settings['poll_interval_ms']));
    $startedAt = microtime(true);
    $deadline = $startedAt + $wait;
    $lookupFailures = 0;
    $successfulLookups = 0;
    $legacyFallbackAvailable = true;
    do {
        $remaining = $deadline - microtime(true);
        $lookupBudget = $wait === 0 ? 1.25 : max(0.15, min(1.25, $remaining));
        try {
            $allowLegacyFallback = $legacyFallbackAvailable;
            $legacyFallbackAvailable = false;
            $candidates = query_candidates_for_txn($txnId, $lookupBudget, $allowLegacyFallback);
            $successfulLookups++;
        } catch (Throwable $lookupError) {
            $lookupFailures++;
            $candidates = [];
        }
        if ($checks['method'] && count($candidates) > 1) {
            $candidates = array_values(array_filter($candidates, function ($candidate) use ($method) {
                return strtolower((string)($candidate['record']['method'] ?? '')) === $method;
            }));
        }
        if (count($candidates) > 1) verify_response(false, 'ambiguous', 'More than one transaction uses this Txn ID across payment methods. Supply the method or enable Payment method comparison.');
        if (count($candidates) === 1) {
            $candidate = $candidates[0]; $record = $candidate['record'];
            if (strtoupper((string)($record['txn_id'] ?? '')) !== $txnId) {
                verify_response(false, 'not_found', 'Transaction ID not found.', null, ['code'=>'TXNID_NOT_FOUND']);
            }
            if (in_array(strtolower((string)($record['status'] ?? 'unused')), ['used', 'success', 'verified', 'refunded'], true)) verify_response(false, 'duplicate', 'Transaction already used.', $record);
            $matches = [];
            if ($checks['txn_id']) $matches['txn_id'] = strtoupper((string)($record['txn_id'] ?? '')) === $txnId;
            if ($checks['number']) $matches['number'] = normalize_number((string)($record['sender'] ?? '')) === $number;
            if ($checks['amount']) $matches['amount'] = abs((float)($record['amount'] ?? -999999) - (float)$amount) < 0.005;
            if ($checks['method']) $matches['method'] = strtolower((string)($record['method'] ?? '')) === $method;
            $all = true; foreach ($matches as $matched) if (!$matched) $all = false;
            if (!$all) {
                try { $record = update_verify_attempt($candidate['path']); } catch (Throwable $ignored) {}
                if (in_array(strtolower((string)($record['status'] ?? '')), ['used','success','verified','refunded'], true)) verify_response(false, 'duplicate', 'Transaction already used.', $record);
                verify_response(false, 'mismatch', 'Transaction found, but one or more enabled values do not match.', $record, ['checks' => $matches]);
            }
            $record['status'] = 'used';
            $record['verified_at'] = time();
            $record['verification_source'] = 'api';
            $record['verification_key_hint'] = (string)($key['record']['key_hint'] ?? '');
            $record['verify_attempt_count'] = (int)($record['verify_attempt_count'] ?? 0) + 1;
            $record['last_verify_attempt_at'] = time();
            $write = fb_request('PUT', $candidate['path'], $record, ['If-Match: ' . $candidate['etag']], [], 3.0);
            if ($write['code'] === 412) {
                $again = query_candidate((string)$record['method'], $txnId, 2.0);
                if ($again && in_array(strtolower((string)($again['record']['status'] ?? '')), ['used', 'success', 'verified', 'refunded'], true)) verify_response(false, 'duplicate', 'Transaction already used.', $again['record']);
                verify_response(false, 'conflict', 'Transaction changed during verification. Retry once.');
            }
            if ($write['code'] < 200 || $write['code'] >= 300) verify_response(false, 'service_unavailable', 'Payment matched but could not be reserved. Retry the request.');
            try { add_sharded_totals('reports/monthly/' . (string)($record['month'] ?? date('Y-m')), ['used_count' => 1], 1.0); } catch (Throwable $ignored) {}
            if (!empty($record['day'])) {
                try { add_sharded_totals('reports/daily/' . (string)$record['day'], ['used_count' => 1], 1.0); } catch (Throwable $ignored) {}
            }
            verify_response(true, 'success', 'Payment verified.', $record);
        }
        if ($wait === 0 || microtime(true) >= $deadline) break;
        $remaining = max(0.0, $deadline - microtime(true));
        if ($remaining <= 0) break;
        usleep((int)(min($poll / 1000.0, $remaining) * 1000000));
    } while (microtime(true) < $deadline);

    $elapsed = max(0.0, microtime(true) - $startedAt);
    if ($lookupFailures > 0 && $successfulLookups === 0) {
        json_out(503, ['status'=>false, 'result'=>'service_unavailable', 'message'=>'Transaction lookup service is temporarily busy. Please retry.', 'retry_after_seconds'=>2, 'waited_seconds'=>round($elapsed,2)]);
    }
    try { add_lookup_attempt($txnId, 1, 0.15); } catch (Throwable $ignored) {}
    verify_response(false, 'not_found', 'Transaction ID not found within the configured wait period.', null, ['code'=>'TXNID_NOT_FOUND', 'retry_after_seconds'=>2, 'waited_seconds'=>round($elapsed,2)]);
}
function handle_api(): void {
    $route = current_route(); $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    if ($route === 'healthz' && $method === 'GET') json_out(200, ['ok' => true, 'service' => 'Payment Bridge Gateway', 'time' => time()]);
    if ($route === 'api/health' && $method === 'GET') {
        if (!config_ready()) json_out(200, ['ok' => true, 'configured' => false, 'firebase' => false, 'service' => 'Payment Bridge Gateway', 'external_url' => envv('RENDER_EXTERNAL_URL'), 'message' => 'Backend environment is incomplete.', 'time' => time()]);
        try {
            fb_get('settings/verification');
            json_out(200, ['ok' => true, 'configured' => true, 'firebase' => true, 'service' => 'Payment Bridge Gateway', 'external_url' => envv('RENDER_EXTERNAL_URL'), 'message' => 'Backend and Firebase are reachable.', 'time' => time()]);
        } catch (Throwable $healthError) {
            json_out(503, ['ok' => false, 'configured' => true, 'firebase' => false, 'service' => 'Payment Bridge Gateway', 'external_url' => envv('RENDER_EXTERNAL_URL'), 'message' => 'Firebase connection failed. Check Render environment variables and Firebase service-account/database access.', 'time' => time()]);
        }
    }
    if (!config_ready()) json_out(503, ['ok' => false, 'message' => 'Backend environment is not configured.']);
    if ($route === 'api/verify') {
        try {
            if ($method === 'GET') api_verify($_GET);
            if ($method === 'POST') api_verify(array_merge($_GET, request_json()));
            json_out(405, ['status' => false, 'result' => 'method_not_allowed', 'message' => 'Use GET or POST.']);
        } catch (Throwable $e) {
            json_out(503, ['status' => false, 'result' => 'service_error', 'message' => 'Verification temporarily unavailable.']);
        }
    }
    if ($method !== 'POST') json_out(405, ['ok' => false, 'message' => 'POST required.']);
    $body = request_json();
    try {
        if ($route === 'api/app/validate') api_app_validate($body);
        if ($route === 'api/heartbeat') api_heartbeat($body);
        if ($route === 'api/disconnect') api_disconnect($body);
        if ($route === 'api/ingest') api_ingest($body);
        json_out(404, ['ok' => false, 'message' => 'API route not found.']);
    } catch (Throwable $e) {
        $msg = $e->getMessage();
        $status = strpos($msg, 'App upload key') !== false ? 401 : (strpos($msg, 'disabled') !== false ? 403 : 500);
        json_out($status, ['ok' => false, 'message' => $status === 500 ? 'Backend request failed. Check Firebase service configuration.' : $msg]);
    }
}
function start_admin_session(): void {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    session_name('PBADMIN');
    session_set_cookie_params(['httponly' => true, 'secure' => $https, 'samesite' => 'Strict', 'lifetime' => 0]);
    session_start();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function redirect_admin(): void { header('Location: /admin'); exit; }
function month_range(string $month): array {
    if (!preg_match('/^\d{4}-\d{2}$/', $month)) $month = date('Y-m');
    $start = strtotime($month . '-01 00:00:00');
    if ($start === false || date('Y-m', $start) !== $month) { $month = date('Y-m'); $start = strtotime($month . '-01'); }
    return [$month, $start, strtotime('+1 month', $start) - 1];
}
function month_transactions(string $month, int $limit = 5000): array {
    [$m, $start, $end] = month_range($month);
    return fb_query('payment_transactions', ['orderBy' => '"created_at"', 'startAt' => (string)$start, 'endAt' => (string)$end, 'limitToLast' => (string)$limit]);
}
function monthly_shards(string $root, string $month): array {
    $data = fb_get($root . '/' . $month . '/shards'); $sum = [];
    foreach ($data as $row) if (is_array($row)) foreach ($row as $k => $v) $sum[$k] = ($sum[$k] ?? 0) + (float)$v;
    return $sum;
}
function range_transactions(int $start, int $end, int $limit = 12000): array {
    $limit = max(100, min(20000, $limit));
    return fb_query('payment_transactions', ['orderBy' => '"created_at"', 'startAt' => (string)$start, 'endAt' => (string)$end, 'limitToLast' => (string)$limit]);
}
function sum_shards_at(string $path): array {
    $data = fb_get($path . '/shards'); $sum = [];
    foreach ($data as $row) if (is_array($row)) foreach ($row as $key => $value) $sum[$key] = ($sum[$key] ?? 0) + (float)$value;
    return $sum;
}
function period_shards(string $monthlyRoot, string $dailyRoot, string $period, string $month, int $year, int $start, int $end): array {
    $sum = [];
    $paths = [];
    if ($period === '7d') {
        for ($day = $start; $day <= $end; $day = strtotime('+1 day', $day)) $paths[] = [$dailyRoot, date('Y-m-d', $day)];
    } elseif ($period === 'year') {
        for ($m = 1; $m <= 12; $m++) $paths[] = [$monthlyRoot, sprintf('%04d-%02d', $year, $m)];
    } else $paths[] = [$monthlyRoot, $month];
    foreach ($paths as [$root, $key]) {
        $part = sum_shards_at($root . '/' . $key);
        foreach ($part as $field => $value) $sum[$field] = ($sum[$field] ?? 0) + (float)$value;
    }
    return $sum;
}
function money(float $amount): string { return '৳' . number_format($amount, 2); }
function admin_page(): void {
    start_admin_session();
    $flash = (string)($_SESSION['flash'] ?? ''); $newAppKey = (string)($_SESSION['new_app_key'] ?? ''); $newVerifyKey = (string)($_SESSION['new_verify_key'] ?? '');
    unset($_SESSION['flash'], $_SESSION['new_app_key'], $_SESSION['new_verify_key']);
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'login') {
            if (envv('PB_ADMIN_PASSWORD') !== '' && hash_equals(envv('PB_ADMIN_PASSWORD'), (string)($_POST['password'] ?? ''))) {
                session_regenerate_id(true); $_SESSION['admin'] = true; $_SESSION['csrf'] = bin2hex(random_bytes(32)); $_SESSION['flash'] = 'Welcome back.';
            } else $_SESSION['flash'] = 'Incorrect admin password.';
            redirect_admin();
        }
        if ($action === 'logout') {
            if (empty($_SESSION['admin']) || !hash_equals((string)$_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) { http_response_code(403); exit('Forbidden'); }
            $_SESSION = []; session_destroy(); redirect_admin();
        }
        if (empty($_SESSION['admin']) || !hash_equals((string)$_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) { http_response_code(403); exit('Forbidden'); }
        try {
            if ($action === 'create_app_key' || $action === 'create_verify_key') {
                $isApp = $action === 'create_app_key';
                $prefix = $isApp ? 'PBU-' : 'PBV-';
                $rawKey = $prefix . strtoupper(bin2hex(random_bytes(24)));
                $hash = key_hash($rawKey);
                $path = $isApp ? 'settings/app_upload_keys/' . $hash : 'settings/verification_api_keys/' . $hash;
                $record = ['active' => true, 'label' => u_substr(trim((string)($_POST['label'] ?? '')), 0, 80), 'key_hint' => substr($rawKey, 0, 9) . '…' . substr($rawKey, -6), 'created_at' => time(), 'last_used_at' => 0, 'usage_count' => 0, 'multi_device' => true];
                if (!$isApp) {
                    $record['wait_seconds'] = max(0, min(60, (int)($_POST['wait_seconds'] ?? 10)));
                    $record['poll_interval_ms'] = max(250, min(5000, (int)($_POST['poll_interval_ms'] ?? 1000)));
                    $record['rate_limit_per_min'] = max(10, min(300, (int)($_POST['rate_limit_per_min'] ?? 120)));
                }
                $record = array_merge($record, encrypt_admin_key($rawKey));
                if (!fb_create_only($path, $record)) throw new RuntimeException('Key collision; try again.');
                if ($isApp) $_SESSION['new_app_key'] = $rawKey; else $_SESSION['new_verify_key'] = $rawKey;
                $_SESSION['flash'] = $isApp ? 'App upload key created. The same key works on multiple phones.' : 'Verification API key created. It can be used by multiple websites and bots.';
            } elseif ($action === 'update_verify_key_timing') {
                $hash = strtolower(preg_replace('/[^a-f0-9]/', '', (string)($_POST['hash'] ?? '')));
                if (strlen($hash) !== 64) throw new RuntimeException('Invalid verification API key.');
                $path = 'settings/verification_api_keys/' . $hash;
                $existing = fb_get($path);
                if (empty($existing['active'])) throw new RuntimeException('Verification API key is inactive.');
                fb_write('PATCH', $path, [
                    'wait_seconds' => max(0, min(60, (int)($_POST['wait_seconds'] ?? 10))),
                    'poll_interval_ms' => max(250, min(5000, (int)($_POST['poll_interval_ms'] ?? 1000))),
                    'rate_limit_per_min' => max(10, min(300, (int)($_POST['rate_limit_per_min'] ?? 120))),
                    'timing_updated_at' => time()
                ]);
                $_SESSION['flash'] = 'API key request timing updated.';
            } elseif (in_array($action, ['revoke_app_key','revoke_verify_key','delete_app_key','delete_verify_key'], true)) {
                $hash = strtolower(preg_replace('/[^a-f0-9]/', '', (string)($_POST['hash'] ?? '')));
                if (strlen($hash) !== 64) throw new RuntimeException('Invalid key.');
                $isAppKey = ($action === 'revoke_app_key' || $action === 'delete_app_key');
                $path = ($isAppKey ? 'settings/app_upload_keys/' : 'settings/verification_api_keys/') . $hash;
                if (strpos($action, 'delete_') === 0) {
                    if ($isAppKey) {
                        $allDevices = fb_get('devices');
                        foreach ($allDevices as $deviceId => $deviceRecord) {
                            if (!is_array($deviceRecord) || !hash_equals($hash, (string)($deviceRecord['app_key_hash'] ?? ''))) continue;
                            fb_write('PATCH', 'devices/' . (string)$deviceId, [
                                'active' => false,
                                'connection_state' => 'key_deleted',
                                'key_deleted_at' => time(),
                                'app_key_hash' => ''
                            ]);
                        }
                    }
                    fb_delete($path);
                    $_SESSION['flash'] = $isAppKey ? 'App upload key permanently deleted; linked devices marked inactive.' : 'Verification API key permanently deleted.';
                } else {
                    fb_write('PATCH', $path, ['active' => false, 'revoked_at' => time()]);
                    $_SESSION['flash'] = 'Key revoked.';
                }
            } elseif ($action === 'save_verification') {
                $checks = ['verify_number' => isset($_POST['verify_number']), 'verify_amount' => isset($_POST['verify_amount']), 'verify_txn_id' => isset($_POST['verify_txn_id']), 'verify_method' => isset($_POST['verify_method'])];
                fb_write('PATCH', 'settings/verification', array_merge($checks, [
                    'wait_seconds' => max(0, min(60, (int)($_POST['wait_seconds'] ?? 10))),
                    'poll_interval_ms' => max(250, min(5000, (int)($_POST['poll_interval_ms'] ?? 1000)))
                ]));
                $_SESSION['flash'] = 'Verification settings saved.';
            } elseif ($action === 'status_update') {
                $key = strtolower(preg_replace('/[^a-f0-9]/', '', (string)($_POST['txn_key'] ?? '')));
                $status = strtolower((string)($_POST['status'] ?? ''));
                if (strlen($key) !== 64 || !in_array($status, ['unused', 'used', 'pending', 'failed', 'refunded'], true)) throw new RuntimeException('Invalid transaction update.');
                $oldRecord = fb_get('payment_transactions/' . $key);
                $oldStatus = strtolower((string)($oldRecord['status'] ?? 'unused'));
                fb_write('PATCH', 'payment_transactions/' . $key, ['status' => $status, 'admin_updated_at' => time()]);
                $wasUsed = in_array($oldStatus, ['used','success','verified'], true);
                $isUsed = in_array($status, ['used','success','verified'], true);
                if ($wasUsed !== $isUsed) {
                    $monthForStatus = (string)($oldRecord['month'] ?? date('Y-m'));
                    try { add_sharded_totals('reports/monthly/' . $monthForStatus, ['used_count' => $isUsed ? 1 : -1]); } catch (Throwable $ignored) {}
                    $dayForStatus = (string)($oldRecord['day'] ?? date('Y-m-d'));
                    try { add_sharded_totals('reports/daily/' . $dayForStatus, ['used_count' => $isUsed ? 1 : -1]); } catch (Throwable $ignored) {}
                }
                $_SESSION['flash'] = 'Transaction status updated.';
            } elseif ($action === 'device_toggle') {
                $id = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['device_id'] ?? ''));
                if (!valid_device_id($id)) throw new RuntimeException('Invalid installation ID.');
                $blocked = (string)($_POST['blocked'] ?? '') === '1';
                fb_write('PATCH', 'devices/' . $id, ['blocked' => $blocked, 'active' => !$blocked, 'connection_state' => $blocked ? 'blocked' : 'enabled']);
                $_SESSION['flash'] = $blocked ? 'Device blocked.' : 'Device enabled.';
            }
        } catch (Throwable $e) { $_SESSION['flash'] = 'Action failed: ' . $e->getMessage(); }
        redirect_admin();
    }

    $loggedIn = !empty($_SESSION['admin']);
    if (!$loggedIn) {
        ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment Bridge Login</title><style>
        *{box-sizing:border-box}body{margin:0;background:#070d18;color:#eff6ff;font:15px system-ui;display:grid;place-items:center;min-height:100vh;padding:20px}.login{width:min(420px,100%);background:#101b2d;border:1px solid #263955;border-radius:22px;padding:28px;box-shadow:0 25px 80px #0008}.brand{font-size:12px;letter-spacing:3px;color:#47d7aa;font-weight:800}.login h1{margin:10px 0 6px;font-size:27px}.muted{color:#98a9c0;font-size:13px}input,button{width:100%;padding:13px;border-radius:12px;border:1px solid #30435f;background:#0a1424;color:#eff6ff;font:inherit;margin-top:10px}button{background:#15b98a;color:#04140f;font-weight:800;border:0;cursor:pointer}
        </style></head><body><form class="login" method="post"><div class="brand">PB / GETWAY</div><h1>Gateway Admin</h1><div class="muted">Sign in to manage payments, API keys and reports.</div><input type="hidden" name="action" value="login"><input type="password" name="password" placeholder="Admin password" required autocomplete="current-password"><button>Sign in</button><p class="muted">Secure server-side session · Firebase Realtime Database</p></form></body></html><?php
        return;
    }

    $month = (string)($_GET['month'] ?? date('Y-m')); [$month, $monthStart, $monthEnd] = month_range($month);
    $period = (string)($_GET['period'] ?? 'month');
    if (!in_array($period, ['7d','month','year'], true)) $period = 'month';
    $reportYear = max(2020, min((int)date('Y') + 1, (int)($_GET['year'] ?? date('Y'))));
    if ($period === '7d') {
        $periodEnd = strtotime(date('Y-m-d 23:59:59'));
        $periodStart = strtotime('-6 days', strtotime(date('Y-m-d 00:00:00')));
        $periodLabel = date('d M', $periodStart) . ' – ' . date('d M Y', $periodEnd);
    } elseif ($period === 'year') {
        $periodStart = strtotime(sprintf('%04d-01-01 00:00:00', $reportYear));
        $periodEnd = strtotime(sprintf('%04d-12-31 23:59:59', $reportYear));
        $periodLabel = (string)$reportYear;
    } else {
        $periodStart = $monthStart; $periodEnd = $monthEnd; $periodLabel = $month;
    }
    $tab = (string)($_GET['tab'] ?? 'overview');
    $allowedTabs = ['overview','transactions','unverified','duplicates','sms','api','devices','data','settings'];
    if (!in_array($tab, $allowedTabs, true)) $tab = 'overview';
    $appKeys = $verifyKeys = $devices = $transactions = $smsRows = $duplicateRows = $apiMetrics = $reportTotals = $firebaseDataView = $simRegistry = [];
    $dataNode = strtolower((string)($_GET['node'] ?? 'verification'));
    if (!in_array($dataNode, ['verification','devices','app_keys','api_keys','monthly_report','monthly_api'], true)) $dataNode = 'verification';
    $verification = ['verify_number' => false, 'verify_amount' => true, 'verify_txn_id' => true, 'verify_method' => true, 'wait_seconds' => 10, 'poll_interval_ms' => 1000];
    $loadError = '';
    if (config_ready()) {
        try {
            $appKeys = fb_get('settings/app_upload_keys');
            $verifyKeys = fb_get('settings/verification_api_keys');
            $devices = fb_get('devices');
            $verification = array_merge($verification, fb_get('settings/verification'));
            $transactions = range_transactions($periodStart, $periodEnd, 20000);
            $smsRows = fb_query('sms_messages', ['orderBy' => '"created_at"', 'startAt' => (string)$periodStart, 'endAt' => (string)$periodEnd, 'limitToLast' => '2000']);
            $duplicateRows = fb_query('duplicate_events', ['orderBy' => '"created_at"', 'startAt' => (string)$periodStart, 'endAt' => (string)$periodEnd, 'limitToLast' => '2000']);
            $apiMetrics = period_shards('metrics/api_monthly', 'metrics/api_daily', $period, $month, $reportYear, $periodStart, $periodEnd);
            $reportTotals = period_shards('reports/monthly', 'reports/daily', $period, $month, $reportYear, $periodStart, $periodEnd);
            $simRegistry = fb_get('reports/sim_registry');
            $dataPaths = ['verification'=>'settings/verification','devices'=>'devices','app_keys'=>'settings/app_upload_keys','api_keys'=>'settings/verification_api_keys','monthly_report'=>'reports/monthly/' . $month . '/shards','monthly_api'=>'metrics/api_monthly/' . $month . '/shards'];
            $firebaseDataView = fb_get($dataPaths[$dataNode]);
            uasort($transactions, function ($a, $b) { return (int)($b['created_at'] ?? 0) <=> (int)($a['created_at'] ?? 0); });
            uasort($smsRows, function ($a, $b) { return (int)($b['created_at'] ?? 0) <=> (int)($a['created_at'] ?? 0); });
        } catch (Throwable $e) { $loadError = $e->getMessage(); }
    } else $loadError = 'Set Firebase Database URL, service account JSON, PB_KEY_PEPPER and PB_ADMIN_PASSWORD in hosting environment.';

    if (isset($_GET['export']) && $_GET['export'] === 'transactions') {
        header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="payment-transactions-' . $period . '-' . $periodLabel . '.csv"');
        $out = fopen('php://output', 'w'); fputcsv($out, ['amount','sender','sender_role','txn_id','method','sim_slot','sim_number','sim_carrier','transaction_type','direction','status','verify_attempt_count','transaction_at','received_at']);
        foreach ($transactions as $tx) if (is_array($tx)) fputcsv($out, [$tx['amount'] ?? 0, $tx['sender'] ?? '', $tx['counterparty_role'] ?? '', $tx['txn_id'] ?? '', $tx['method'] ?? '', $tx['sim_slot'] ?? '', $tx['sim_number'] ?? '', $tx['sim_carrier'] ?? '', $tx['transaction_type'] ?? '', $tx['direction'] ?? '', $tx['status'] ?? '', $tx['verify_attempt_count'] ?? 0, $tx['transaction_at'] ?? '', $tx['received_at'] ?? '']);
        fclose($out); exit;
    }

    $incoming = (float)($reportTotals['incoming_amount'] ?? 0); $outgoing = (float)($reportTotals['outgoing_amount'] ?? 0);
    $incomingCount = (int)($reportTotals['incoming_count'] ?? 0); $outgoingCount = (int)($reportTotals['outgoing_count'] ?? 0);
    $paymentCount = (int)($reportTotals['payment_count'] ?? count($transactions));
    $smsCount = (int)($reportTotals['sms_count'] ?? 0);
    if ($smsCount === 0 && count($smsRows) > 0) $smsCount = count($smsRows);
    $duplicateTxnCount = (int)($reportTotals['duplicate_txn_count'] ?? 0);
    if (count($transactions) > 0 && count($transactions) < 20000) {
        $incoming = 0.0; $outgoing = 0.0; $incomingCount = 0; $outgoingCount = 0; $paymentCount = count($transactions);
        foreach ($transactions as $tx) if (is_array($tx)) {
            $direction = strtolower((string)($tx['direction'] ?? ''));
            if ($direction === 'credit') { $incoming += (float)($tx['amount'] ?? 0); $incomingCount++; }
            if ($direction === 'debit') { $outgoing += (float)($tx['amount'] ?? 0); $outgoingCount++; }
        }
    }
    $simSummary = [];
    $simAggregates = [];
    foreach ($reportTotals as $aggregateField => $aggregateValue) {
        if (preg_match('/^sim_([a-f0-9]{24})_(payment_count|incoming_count|outgoing_count|incoming_amount|outgoing_amount)$/', (string)$aggregateField, $match)) {
            $simAggregates[$match[1]][$match[2]] = (float)$aggregateValue;
        }
    }
    foreach ($simRegistry as $registeredKey => $meta) {
        if (!is_array($meta)) continue;
        $prefix = substr((string)($meta['sim_key'] ?? $registeredKey), 0, 24);
        if ($prefix === '' || !isset($simAggregates[$prefix])) continue;
        $aggregate = $simAggregates[$prefix];
        $simSummary[(string)$registeredKey] = [
            'label' => trim((string)($meta['label'] ?? '')) ?: 'SIM ' . (string)($meta['slot'] ?? 'unknown'),
            'number' => (string)($meta['number'] ?? ''), 'carrier' => (string)($meta['carrier'] ?? ''),
            'slot' => (string)($meta['slot'] ?? ''),
            'count' => (int)($aggregate['payment_count'] ?? 0),
            'incoming' => (float)($aggregate['incoming_amount'] ?? 0),
            'outgoing' => (float)($aggregate['outgoing_amount'] ?? 0),
            'incoming_count' => (int)($aggregate['incoming_count'] ?? 0),
            'outgoing_count' => (int)($aggregate['outgoing_count'] ?? 0),
            'aggregate' => true
        ];
        unset($simAggregates[$prefix]);
    }
    foreach ($simAggregates as $prefix => $aggregate) {
        $simKey = 'aggregate-' . $prefix;
        $simSummary[$simKey] = [
            'label' => 'SIM aggregate ' . $prefix, 'number' => '', 'carrier' => '', 'slot' => '',
            'count' => (int)($aggregate['payment_count'] ?? 0),
            'incoming' => (float)($aggregate['incoming_amount'] ?? 0),
            'outgoing' => (float)($aggregate['outgoing_amount'] ?? 0),
            'incoming_count' => (int)($aggregate['incoming_count'] ?? 0),
            'outgoing_count' => (int)($aggregate['outgoing_count'] ?? 0),
            'aggregate' => true
        ];
    }
    foreach ($transactions as $tx) if (is_array($tx)) {
        $simKey = (string)($tx['sim_key'] ?? '');
        if ($simKey === '') $simKey = 'legacy-unknown';
        $prefix = preg_match('/^[a-f0-9]{64}$/i', $simKey) ? substr($simKey, 0, 24) : '';
        if ($prefix !== '' && isset($simAggregates[$prefix])) continue;
        if ($prefix !== '' && isset($simSummary[$simKey]) && !empty($simSummary[$simKey]['aggregate'])) continue;
        if (!isset($simSummary[$simKey])) {
            $label = trim((string)($tx['sim_label'] ?? ''));
            $number = trim((string)($tx['sim_number'] ?? ''));
            $carrier = trim((string)($tx['sim_carrier'] ?? ''));
            $slot = trim((string)($tx['sim_slot'] ?? ''));
            if ($label === '') $label = $number !== '' ? $number : ($carrier !== '' ? $carrier : ($slot !== '' && $slot !== 'unknown' ? 'SIM ' . $slot : 'Legacy / unknown SIM'));
            $simSummary[$simKey] = ['label'=>$label, 'number'=>$number, 'carrier'=>$carrier, 'slot'=>$slot, 'count'=>0, 'incoming'=>0.0, 'outgoing'=>0.0, 'incoming_count'=>0, 'outgoing_count'=>0, 'aggregate'=>false];
        }
        $simSummary[$simKey]['count']++;
        $direction = strtolower((string)($tx['direction'] ?? ''));
        if ($direction === 'credit') { $simSummary[$simKey]['incoming'] += (float)($tx['amount'] ?? 0); $simSummary[$simKey]['incoming_count']++; }
        if ($direction === 'debit') { $simSummary[$simKey]['outgoing'] += (float)($tx['amount'] ?? 0); $simSummary[$simKey]['outgoing_count']++; }
    }
    uasort($simSummary, function($a,$b) { return ((float)$b['incoming'] + (float)$b['outgoing']) <=> ((float)$a['incoming'] + (float)$a['outgoing']); });
    $rangeTruncated = count($transactions) >= 20000;
    $unverified = [];
    foreach ($transactions as $key => $tx) if (is_array($tx) && strtolower((string)($tx['status'] ?? 'unused')) === 'unused' && (int)($tx['verify_attempt_count'] ?? 0) === 0) $unverified[$key] = $tx;
    $verifiedCount = 0; $allTxnIds = [];
    $usedCount = (int)($reportTotals['used_count'] ?? 0);
    if (count($transactions) < 20000 || !array_key_exists('used_count', $reportTotals)) $usedCount = 0;
    foreach ($transactions as $tx) if (is_array($tx)) {
        if ((count($transactions) < 20000 || !array_key_exists('used_count', $reportTotals))
            && in_array(strtolower((string)($tx['status'] ?? '')), ['used','success','verified'], true)) $usedCount++;
        $id = strtoupper((string)($tx['txn_id'] ?? '')); if ($id !== '') $allTxnIds[$id] = true;
        if ((int)($tx['verify_attempt_count'] ?? 0) > 0) $verifiedCount++;
    }
    $apiRequests = (int)($apiMetrics['requests'] ?? 0);
    $apiSuccess = (int)($apiMetrics['result_success'] ?? 0);
    $search = u_lower(trim((string)($_GET['q'] ?? ''))); $methodFilter = strtolower(trim((string)($_GET['method'] ?? ''))); $statusFilter = strtolower(trim((string)($_GET['status'] ?? ''))); $typeFilter = strtolower(trim((string)($_GET['type'] ?? ''))); $directionFilter = strtolower(trim((string)($_GET['direction'] ?? ''))); $simFilter = strtolower(trim((string)($_GET['sim'] ?? '')));
    $filtered = [];
    foreach (($tab === 'unverified' ? $unverified : $transactions) as $k => $tx) {
        if (!is_array($tx)) continue;
        if ($methodFilter !== '' && strtolower((string)($tx['method'] ?? '')) !== $methodFilter) continue;
        if ($statusFilter !== '' && strtolower((string)($tx['status'] ?? '')) !== $statusFilter) continue;
        if ($typeFilter !== '' && strtolower((string)($tx['transaction_type'] ?? '')) !== $typeFilter) continue;
        if ($directionFilter !== '' && strtolower((string)($tx['direction'] ?? '')) !== $directionFilter) continue;
        if ($simFilter !== '' && strtolower((string)($tx['sim_key'] ?? 'legacy-unknown')) !== $simFilter) continue;
        $hay = u_lower(implode(' ', [(string)($tx['txn_id'] ?? ''),(string)($tx['sender'] ?? ''),(string)($tx['method'] ?? ''),(string)($tx['sim_number'] ?? ''),(string)($tx['sim_carrier'] ?? '')]));
        if ($search !== '' && strpos($hay, $search) === false) continue;
        $filtered[$k] = $tx;
    }
    $filtered = array_slice($filtered, 0, 250, true);
    $csrf = (string)$_SESSION['csrf'];
    $tabs = ['overview'=>'Overview','transactions'=>'Transactions','unverified'=>'Not API-checked','sms'=>'Payment SMS','api'=>'API & Keys','devices'=>'Devices','duplicates'=>'Duplicates','data'=>'Firebase Data','settings'=>'Settings'];
    $renderExternalUrl = rtrim(envv('RENDER_EXTERNAL_URL'), '/');
    $badge = function ($value, $good = true) { return '<span class="badge ' . ($good ? 'good' : 'bad') . '">' . h((string)$value) . '</span>'; };
    $devicesNeedAttention = 0; $pendingQueueTotal = 0;
    foreach ($devices as $deviceSummary) {
        if (!is_array($deviceSummary)) continue;
        $pendingQueueTotal += max(0, (int)($deviceSummary['pending_queue_count'] ?? 0));
        if (!empty($deviceSummary['blocked']) || empty($deviceSummary['active'])
            || empty($deviceSummary['permission_sms']) || empty($deviceSummary['permission_notifications'])
            || empty($deviceSummary['permission_battery_exempt']) || !empty($deviceSummary['background_restricted'])
            || empty($deviceSummary['network_connected'])) $devicesNeedAttention++;
    }
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#080f1c"><title>Payment Bridge · Gateway</title><style>
    :root{color-scheme:dark;--bg:#070d18;--side:#0b1423;--panel:#101d30;--panel2:#14243a;--line:#263a55;--text:#edf5ff;--muted:#91a4bf;--mint:#2bd5a1;--blue:#5792ff;--amber:#f1bd62;--red:#fa7180;--shadow:0 18px 46px #0005}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#183153 0,transparent 35%),var(--bg);color:var(--text);font:14px Inter,system-ui,Arial}.shell{display:grid;grid-template-columns:238px minmax(0,1fr);min-height:100vh}.side{background:#091321;border-right:1px solid var(--line);padding:23px 14px;position:sticky;top:0;height:100vh}.brand{display:flex;align-items:center;gap:11px;padding:4px 9px 25px}.logo{width:39px;height:39px;border-radius:13px;background:linear-gradient(135deg,#27d5a0,#168fbd);display:grid;place-items:center;color:#03251b;font-weight:1000;font-size:17px}.brand strong{display:block;font-size:15px;letter-spacing:.5px}.brand small{color:var(--muted);font-size:10px;letter-spacing:1.6px}.nav a{display:flex;gap:11px;align-items:center;padding:12px 13px;color:#a9bad0;text-decoration:none;border-radius:11px;margin:4px 0;font-weight:650}.nav a.active,.nav a:hover{background:#142840;color:#eaf5ff}.nav .ico{width:20px;text-align:center;color:var(--mint)}.sidebottom{position:absolute;bottom:20px;left:14px;right:14px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding:15px 8px}.main{min-width:0;padding:24px clamp(14px,3vw,38px) 60px;max-width:1600px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;gap:14px;align-items:center;margin-bottom:22px}.eyebrow{color:var(--mint);font-size:10px;letter-spacing:2px;font-weight:800}.top h1{font-size:26px;margin:4px 0}.sub{color:var(--muted);font-size:12px}.topright{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.badge{display:inline-flex;align-items:center;padding:5px 9px;border-radius:30px;font-size:10px;font-weight:850;letter-spacing:.5px;background:#203047;color:#c6d7ec}.badge.good{background:#103b32;color:#6ce7c1}.badge.bad{background:#48242d;color:#ffadb6}.badge.warn{background:#45351e;color:#ffd78c}.panel{background:linear-gradient(180deg,#122139,#0e1a2c);border:1px solid var(--line);border-radius:17px;box-shadow:var(--shadow);padding:18px;margin-bottom:16px}.panelhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:15px}.panel h2{font-size:15px;margin:0}.panel p{color:var(--muted);font-size:12px;line-height:1.6}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:16px}.stat{background:linear-gradient(145deg,#142640,#0e1b2d);border:1px solid var(--line);padding:17px;border-radius:15px;min-width:0}.stat .label{color:var(--muted);font-size:11px}.stat .value{font-weight:850;font-size:clamp(18px,2.1vw,25px);margin:8px 0 4px;overflow-wrap:anywhere}.stat .hint{font-size:10px;color:var(--muted)}.mint{color:var(--mint)}.blue{color:#88b5ff}.amber{color:var(--amber)}.red{color:var(--red)}.row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.row form{margin:0}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}label{display:block;color:#a9bad0;font-size:11px;margin:9px 0 5px}input,select,button,.btn{font:inherit;border:1px solid #304663;border-radius:10px;padding:10px 11px;background:#0a1627;color:var(--text);width:100%;min-width:0}input[type=checkbox]{width:auto;accent-color:var(--mint);margin-right:7px}button,.btn{background:linear-gradient(135deg,#25c99a,#159b88);color:#03251d;border:0;font-weight:850;cursor:pointer;text-decoration:none;text-align:center;display:inline-block}button.secondary,.btn.secondary{background:#263b57;color:#e6f1ff}button.danger{background:#7c2f3d;color:#fff}button.small{width:auto;padding:7px 10px;font-size:11px}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:720px;font-size:12px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #24364e;white-space:nowrap}.message-cell{white-space:normal;min-width:260px;max-width:460px;overflow-wrap:anywhere;word-break:break-word;line-height:1.5}.message-cell summary{cursor:pointer;white-space:normal;overflow-wrap:anywhere;max-width:430px}.full-message{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;max-width:460px;padding:9px;margin-top:7px;border:1px solid var(--line);border-radius:8px;background:#081526}.wrap-cell{white-space:normal;overflow-wrap:anywhere;word-break:break-word;max-width:220px}.sub{overflow-wrap:anywhere}th{background:#14243a;color:#9db1ca;font-size:10px;text-transform:uppercase;letter-spacing:.7px}tr:last-child td{border-bottom:0}.muted{color:var(--muted)}.keybox{font:800 14px ui-monospace,monospace;overflow-wrap:anywhere;word-break:break-word;background:#071321;border:1px dashed #318f79;padding:13px;border-radius:10px;margin:10px 0}.notice{overflow-wrap:anywhere;word-break:break-word;border:1px solid #267d68;background:#0d302b;color:#b8ffe9;padding:13px;border-radius:12px;margin-bottom:15px}.warning{border-color:#735629;background:#332817;color:#ffe2a9}.sectionnote{font-size:11px;color:var(--muted);line-height:1.6}.barrow{display:grid;grid-template-columns:78px 1fr 90px;gap:10px;align-items:center;margin:10px 0;font-size:11px;color:var(--muted)}.bar{height:8px;background:#1b2b42;border-radius:10px;overflow:hidden}.bar i{height:100%;display:block;background:linear-gradient(90deg,#21bd9a,#5f9dff);border-radius:10px}.filter{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:9px;align-items:end;margin-bottom:14px}.inlineform{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.inlineform select{width:auto;min-width:110px}.inlineform button{width:auto}.checkgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.checkitem{padding:12px;border:1px solid var(--line);border-radius:11px;background:#0b1728}.checkitem label{margin:0;color:var(--text);font-size:12px}.topmobile{display:none}.empty{padding:27px;text-align:center;color:var(--muted)}@media(max-width:1000px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.shell{grid-template-columns:205px minmax(0,1fr)}}@media(max-width:720px){.shell{display:block}.side{position:relative;width:auto;height:auto;padding:10px;border-right:0;border-bottom:1px solid var(--line)}.brand{padding:5px 8px 12px}.nav{display:flex;overflow:auto;gap:4px;padding-bottom:3px}.nav a{white-space:nowrap;margin:0;padding:10px;font-size:11px}.sidebottom{display:none}.main{padding-top:18px}.top{align-items:flex-start;flex-direction:column}.stats{gap:8px}.stat{padding:13px}.grid2,.grid3{grid-template-columns:1fr}.filter{grid-template-columns:1fr 1fr}.filter .wide{grid-column:1/-1}.checkgrid{grid-template-columns:1fr}}@media(max-width:390px){.stats{grid-template-columns:1fr 1fr}.stat .value{font-size:18px}}
    </style></head><body><div class="shell"><aside class="side"><div class="brand"><div class="logo">PB</div><div><strong>PAYMENT BRIDGE</strong><small>PERSONAL GATEWAY</small></div></div><nav class="nav"><?php foreach ($tabs as $id=>$label): $icons=['overview'=>'◫','transactions'=>'▤','unverified'=>'◷','duplicates'=>'≋','sms'=>'▣','api'=>'⌘','devices'=>'▦','data'=>'◈','settings'=>'⚙']; ?><a class="<?= $tab===$id?'active':'' ?>" href="/admin?tab=<?=h($id)?>&amp;month=<?=h($month)?>&amp;period=<?=h($period)?>&amp;year=<?=h((string)$reportYear)?>"><span class="ico"><?=$icons[$id]?></span><?=h($label)?></a><?php endforeach; ?></nav><div class="sidebottom">Firebase Realtime Database<br>Single database · No SQL</div></aside><main class="main"><header class="top"><div><div class="eyebrow">PAYMENT OPERATIONS / BD</div><h1><?=h($tabs[$tab])?></h1><div class="sub">Selected period: <?=h($periodLabel)?> · Asia/Dhaka<?php if($renderExternalUrl!==''): ?> · Service URL: <?=h($renderExternalUrl)?><?php endif; ?></div></div><div class="topright"><a class="btn secondary small" href="/api/health" target="_blank" rel="noopener">API HEALTH</a><?=$badge(config_ready()?'BACKEND READY':'CONFIG REQUIRED',config_ready())?><form method="post"><input type="hidden" name="action" value="logout"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><button class="secondary small">Sign out</button></form></div></header>
    <?php if ($flash !== ''): ?><div class="notice"><?=h($flash)?></div><?php endif; ?>
    <?php if ($newAppKey !== ''): ?><div class="notice"><b>New App Upload Key — copy now</b><div class="keybox" id="freshappkey"><?=h($newAppKey)?></div><button class="small" onclick="navigator.clipboard.writeText(document.getElementById('freshappkey').innerText)">Copy key</button><p>One key may be entered on many phones. The full key is shown once.</p></div><?php endif; ?>
    <?php if ($newVerifyKey !== ''): ?><div class="notice"><b>New Verification API Key — copy now</b><div class="keybox" id="freshverifykey"><?=h($newVerifyKey)?></div><button class="small" onclick="navigator.clipboard.writeText(document.getElementById('freshverifykey').innerText)">Copy key</button><p>Use this key from server-side website code or Telegram bot. Never expose it in public JavaScript.</p></div><?php endif; ?>
    <?php if ($loadError !== ''): ?><div class="notice warning"><?=h($loadError)?></div><?php endif; ?>
    <form method="get" class="row" style="margin:0 0 16px"><input type="hidden" name="tab" value="<?=h($tab)?>"><label style="margin:0">Report period</label><select name="period" style="max-width:145px"><option value="7d" <?=$period==='7d'?'selected':''?>>Last 7 days</option><option value="month" <?=$period==='month'?'selected':''?>>Month</option><option value="year" <?=$period==='year'?'selected':''?>>Year</option></select><input type="month" name="month" value="<?=h($month)?>" style="max-width:160px"><input type="number" name="year" min="2020" max="<?=date('Y')+1?>" value="<?=h((string)$reportYear)?>" style="max-width:110px"><button class="small">Apply</button><a class="btn secondary small" href="/admin?tab=transactions&amp;period=<?=h($period)?>&amp;month=<?=h($month)?>&amp;year=<?=h((string)$reportYear)?>&amp;export=transactions">Export CSV</a></form>
    <?php if ($tab === 'overview'): ?>
      <div class="stats"><div class="stat"><div class="label">MONEY RECEIVED · CREDIT</div><div class="value mint"><?=h(money($incoming))?></div><div class="hint"><?=number_format($incomingCount)?> incoming transactions</div></div><div class="stat"><div class="label">MONEY SENT · DEBIT</div><div class="value amber"><?=h(money($outgoing))?></div><div class="hint"><?=number_format($outgoingCount)?> outgoing transactions</div></div><div class="stat"><div class="label">PAYMENT TXN IDS</div><div class="value blue"><?=number_format($paymentCount)?></div><div class="hint">Unique Method + Txn ID records</div></div><div class="stat"><div class="label">NOT API-CHECKED</div><div class="value red"><?=number_format(count($unverified))?></div><div class="hint">Payment SMS with no matched API attempt</div></div><div class="stat"><div class="label">API VERIFY REQUESTS</div><div class="value"><?=number_format($apiRequests)?></div><div class="hint"><?=number_format($apiSuccess)?> successful in selected period</div></div><div class="stat"><div class="label">USED / VERIFIED PAYMENTS</div><div class="value mint"><?=number_format($usedCount)?></div><div class="hint">Transactions marked used</div></div><div class="stat"><div class="label">PAYMENT SMS</div><div class="value"><?=number_format($smsCount)?></div><div class="hint">Payment notifications saved</div></div><div class="stat"><div class="label">DUPLICATE TXN</div><div class="value amber"><?=number_format($duplicateTxnCount)?></div><div class="hint">Repeated Method + Txn ID uploads</div></div><div class="stat"><div class="label">APP INSTANCES</div><div class="value"><?=number_format(count($devices))?></div><div class="hint">Installations seen by backend</div></div><div class="stat"><div class="label">API KEYS</div><div class="value"><?=number_format(count(array_filter($verifyKeys, function($v){return is_array($v)&&!empty($v['active']);})))?></div><div class="hint">Active verification keys</div></div></div>
      <div class="grid2"><section class="panel"><div class="panelhead"><h2>Money flow</h2><span class="badge good"><?=h($periodLabel)?></span></div><div class="barrow"><span>Received</span><div class="bar"><i style="width:<?=($incoming+$outgoing)>0?max(2,min(100,100*$incoming/($incoming+$outgoing))):0?>%"></i></div><b><?=h(money($incoming))?></b></div><div class="barrow"><span>Sent</span><div class="bar"><i style="width:<?=($incoming+$outgoing)>0?max(2,min(100,100*$outgoing/($incoming+$outgoing))):0?>%;background:linear-gradient(90deg,#e8ac50,#e46d75)"></i></div><b><?=h(money($outgoing))?></b></div><p>Incoming is counted from SMS parsed as <b>credit</b>; outgoing is counted from <b>debit</b>. Unknown direction is not included in money-flow totals.</p></section><section class="panel"><div class="panelhead"><h2>Payment follow-up</h2><span class="badge warn">Action needed</span></div><p><b class="red"><?=count($unverified)?></b> payments have arrived but no verification request has been matched to their Txn ID (including requests received before SMS sync).</p><p><b><?=number_format($apiMetrics['result_pending'] ?? 0)?></b> pending · <b><?=number_format($apiMetrics['result_failed'] ?? 0)?></b> not found/failed · <b><?=number_format($apiMetrics['result_duplicate'] ?? 0)?></b> duplicate results.</p><a class="btn secondary" href="/admin?tab=unverified&amp;period=<?=h($period)?>&amp;month=<?=h($month)?>&amp;year=<?=h((string)$reportYear)?>">Review unchecked payments</a></section></div>
      <section class="panel"><div class="panelhead"><h2>SIM-wise money flow</h2><span class="badge"><?=count($simSummary)?> lines</span></div><p>Incoming এবং outgoing payment SMS যে SIM slot দিয়ে এসেছে, সেই SIM অনুযায়ী হিসাব। পুরোনো transaction-এ SIM data না থাকলে Legacy / unknown SIM দেখাবে. <?php if($rangeTruncated): ?><b>Note: transaction list is capped at 20,000 records. Current-version SIM totals use daily/monthly aggregates; older records without SIM aggregates are estimated from loaded rows.</b><?php endif;?></p><div class="tablewrap"><table><thead><tr><th>SIM / Carrier</th><th>Number</th><th>Payments</th><th>Received</th><th>Sent</th><th>Net</th></tr></thead><tbody><?php if(!$simSummary):?><tr><td colspan="6" class="empty">No SIM-tagged transactions in this period.</td></tr><?php else: foreach($simSummary as $sim):?><tr><td class="wrap-cell"><?=h((string)$sim['label'])?><?php if($sim['carrier']!==''):?><small class="muted"><?=h((string)$sim['carrier'])?></small><?php endif;?></td><td><?=h((string)($sim['number']!==''?$sim['number']:'Not supplied by Android'))?></td><td><?=number_format((int)$sim['count'])?></td><td class="mint"><?=h(money((float)$sim['incoming']))?></td><td class="amber"><?=h(money((float)$sim['outgoing']))?></td><td><?=h(money((float)$sim['incoming']-(float)$sim['outgoing']))?></td></tr><?php endforeach; endif;?></tbody></table></div></section>
      <section class="panel"><div class="panelhead"><h2>Latest payments</h2><a class="btn secondary small" href="/admin?tab=transactions&amp;period=<?=h($period)?>&amp;month=<?=h($month)?>&amp;year=<?=h((string)$reportYear)?>">View all</a></div><?php if (!$transactions): ?><div class="empty">No payments in this selected period yet.</div><?php else: ?><div class="tablewrap"><table><thead><tr><th>Amount</th><th>Sender</th><th>Sender role</th><th>Txn ID</th><th>Method</th><th>SIM / Line</th><th>Type</th><th>Direction</th><th>Status</th></tr></thead><tbody><?php $n=0; foreach ($transactions as $id=>$tx): if (!is_array($tx)||$n++>=12) continue; ?><tr><td><?=h(money((float)($tx['amount']??0)))?></td><td><?=h((string)($tx['sender']??''))?></td><td><?=h((string)($tx['counterparty_role']??''))?></td><td><?=h((string)($tx['txn_id']??''))?></td><td><?=h(strtoupper((string)($tx['method']??'')))?></td><td class="wrap-cell"><?=h((string)($tx['sim_label']??'Legacy / unknown SIM'))?> <?=h((string)($tx['sim_number']??''))?></td><td><?=h((string)($tx['transaction_type']??''))?></td><td><?=h(strtoupper((string)($tx['direction']??'')))?></td><td><?=$badge(strtoupper((string)($tx['status']??'UNUSED')),($tx['status']??'unused')==='used')?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?></section>
    <?php elseif ($tab === 'transactions' || $tab === 'unverified'): ?>
      <section class="panel"><div class="panelhead"><h2><?=h($tab==='unverified'?'Payments not requested by API':'Payment transactions')?></h2><span class="badge"><?=count($filtered)?> shown</span></div><form class="filter" method="get"><input type="hidden" name="tab" value="<?=h($tab)?>"><input type="hidden" name="month" value="<?=h($month)?>"><input type="hidden" name="period" value="<?=h($period)?>"><input type="hidden" name="year" value="<?=h((string)$reportYear)?>"><div class="wide"><label>Search Txn ID or sender number</label><input name="q" value="<?=h($search)?>" placeholder="Transaction ID / 01XXXXXXXXX"></div><div><label>Method</label><select name="method"><option value="">All methods</option><?php foreach(['bkash','nagad','rocket'] as $m):?><option value="<?=$m?>" <?=$methodFilter===$m?'selected':''?>><?=ucfirst($m)?></option><?php endforeach;?></select></div><div><label>Status</label><select name="status"><option value="">All</option><?php foreach(['unused','used','pending','failed','refunded'] as $s):?><option value="<?=$s?>" <?=$statusFilter===$s?'selected':''?>><?=ucfirst($s)?></option><?php endforeach;?></select></div><div><label>Transaction type</label><select name="type"><option value="">All types</option><?php foreach(['send_money','cash_in','payment_received','cash_out','money_received','bill_payment','add_money','remittance','other_payment'] as $t):?><option value="<?=$t?>" <?=$typeFilter===$t?'selected':''?>><?=h(ucwords(str_replace('_',' ',$t)))?></option><?php endforeach;?></select></div><div><label>Direction</label><select name="direction"><option value="">All</option><?php foreach(['credit','debit','unknown'] as $d):?><option value="<?=$d?>" <?=$directionFilter===$d?'selected':''?>><?=ucfirst($d)?></option><?php endforeach;?></select></div><div><label>SIM / Line</label><select name="sim"><option value="">All SIMs</option><?php foreach($simSummary as $sk=>$sim):?><option value="<?=h((string)$sk)?>" <?= $simFilter===$sk?'selected':'' ?>><?=h((string)$sim['label'])?></option><?php endforeach;?></select></div><div><label>&nbsp;</label><button>Filter</button></div></form><?php if (!$filtered): ?><div class="empty">No transactions match these filters.</div><?php else: ?><div class="tablewrap"><table><thead><tr><th>Amount</th><th>Sender</th><th>Sender role</th><th>Txn ID</th><th>Method</th><th>SIM / Line</th><th>Type</th><th>Direction</th><th>Status</th><th>API attempts</th><th>Received</th><th>Update</th></tr></thead><tbody><?php foreach($filtered as $id=>$tx): ?><tr><td><?=h(money((float)($tx['amount']??0)))?></td><td><?=h((string)($tx['sender']??''))?></td><td><?=h((string)($tx['counterparty_role']??''))?></td><td><?=h((string)($tx['txn_id']??''))?></td><td><?=h(strtoupper((string)($tx['method']??'')))?></td><td class="wrap-cell"><?=h((string)($tx['sim_label']??'Legacy / unknown SIM'))?> <?=h((string)($tx['sim_number']??''))?><?php if(!empty($tx['sim_carrier'])):?> · <?=h((string)$tx['sim_carrier'])?><?php endif;?></td><td><?=h((string)($tx['transaction_type']??''))?></td><td><?=h((string)($tx['direction']??''))?></td><td><?=$badge(strtoupper((string)($tx['status']??'UNUSED')),($tx['status']??'unused')==='used')?></td><td><?=number_format((int)($tx['verify_attempt_count']??0))?></td><td><?=!empty($tx['transaction_at'])?h((string)$tx['transaction_at']):h(date('d/m/Y H:i',(int)($tx['received_at_ms']??0)/1000))?></td><td><form method="post" class="inlineform"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="status_update"><input type="hidden" name="txn_key" value="<?=h((string)$id)?>"><select name="status"><option value="unused">unused</option><option value="used">used</option><option value="pending">pending</option><option value="failed">failed</option><option value="refunded">refunded</option></select><button class="small">Save</button></form></td></tr><?php endforeach;?></tbody></table></div><?php endif;?></section>
    <?php elseif ($tab === 'duplicates'): ?>
      <section class="panel"><div class="panelhead"><h2>Duplicate transaction attempts</h2><span class="badge warn"><?=count($duplicateRows)?> events</span></div><p>একই Method + Transaction ID আগে পাওয়া থাকলে নতুন SMS overwrite করা হয় না। একই SMS retry হলে আবার duplicate count হয় না; আলাদা SMS-এ একই Txn ID এলে এখানে দেখা যায়।</p><div class="tablewrap"><table><thead><tr><th>Method</th><th>Txn ID</th><th>Amount</th><th>Installation</th><th>Detected</th></tr></thead><tbody><?php foreach($duplicateRows as $dup):if(!is_array($dup))continue;?><tr><td><?=h(strtoupper((string)($dup['method']??'')))?></td><td><?=h((string)($dup['txn_id']??''))?></td><td><?=h(money((float)($dup['amount']??0)))?></td><td><?=h(substr((string)($dup['device_id']??''),0,16))?></td><td><?=!empty($dup['stored_at'])?h(date('d/m/Y H:i',(int)$dup['stored_at'])):'-'?></td></tr><?php endforeach;?></tbody></table></div></section>
    <?php elseif ($tab === 'sms'): ?>
      <section class="panel"><div class="panelhead"><h2>Payment SMS in selected period</h2><span class="badge"><?=count($smsRows)?> records<?=count($smsRows)>=2000?' · latest 2,000':''?></span></div><div class="tablewrap"><table><thead><tr><th>Amount</th><th>Counterparty</th><th>Txn ID</th><th>Method</th><th>SMS Sender</th><th>SIM / Line</th><th>Type</th><th>Message</th></tr></thead><tbody><?php foreach($smsRows as $sms):if(!is_array($sms))continue;?><tr><td><?=h(money((float)($sms['amount']??0)))?></td><td><?=h((string)($sms['sender']??''))?></td><td><?=h((string)($sms['txn_id']??''))?></td><td><?=h(strtoupper((string)($sms['method']??'')))?></td><td><?=h((string)($sms['sms_sender']??''))?></td><td class="wrap-cell"><?=h((string)($sms['sim_label']??'Legacy / unknown SIM'))?> <?=h((string)($sms['sim_number']??''))?></td><td><?=h((string)($sms['transaction_type']??''))?></td><td class="message-cell"><details><summary><?=h(u_substr((string)($sms['message']??''),0,110))?><?=u_substr((string)($sms['message']??''),110,1)!=='' ? '…' : ''?></summary><div class="full-message"><?=nl2br(h((string)($sms['message']??'')))?></div></details></td></tr><?php endforeach;?></tbody></table></div></section>
    <?php elseif ($tab === 'api'): ?>
      <div class="grid2"><section class="panel"><div class="panelhead"><h2>App upload keys</h2><span class="badge good">Multi-device</span></div><p>একই App Key একাধিক Android ফোনে ব্যবহার করা যাবে। Key দিয়ে শুধু payment SMS upload, heartbeat ও device status নিয়ন্ত্রণ হবে।</p><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="create_app_key"><label>Key label</label><input name="label" placeholder="Main Android / Backup phones"><button>Create app key</button></form><div class="tablewrap" style="margin-top:12px"><table><thead><tr><th>Key Hint</th><th>Label</th><th>Status</th><th>Copy key</th><th>Action</th></tr></thead><tbody><?php foreach($appKeys as $hash=>$k):if(!is_array($k))continue;$copySecret=decrypt_admin_key($k);?><tr><td><?=h((string)($k['key_hint']??''))?></td><td><?=h((string)($k['label']??''))?></td><td><?=$badge(!empty($k['active'])?'ACTIVE':'REVOKED',!empty($k['active']))?></td><td><?php if($copySecret!==''):?><button type="button" class="secondary small" data-secret="<?=h($copySecret)?>" onclick="navigator.clipboard.writeText(this.dataset.secret).then(()=>this.textContent='Copied')">Copy key</button><?php else:?><span class="muted">Legacy key</span><?php endif;?></td><td><?php if(!empty($k['active'])):?><form method="post" style="display:inline-block"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="revoke_app_key"><input type="hidden" name="hash" value="<?=h((string)$hash)?>"><button class="danger small">Revoke</button></form><?php endif;?><form method="post" style="display:inline-block" onsubmit="return confirm('Permanently delete this App Upload Key? Devices using it will lose access.')"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="delete_app_key"><input type="hidden" name="hash" value="<?=h((string)$hash)?>"><button class="danger small">Delete</button></form></td></tr><?php endforeach;?></tbody></table></div></section><section class="panel"><div class="panelhead"><h2>Verification API keys</h2><span class="badge good">Multi-client</span></div><p>Website, Telegram Bot বা অন্য Backend থেকে payment verify করার জন্য। API Key একইসঙ্গে একাধিক integration ব্যবহার করতে পারে। প্রতিটি Key-এর Wait ও Polling আলাদাভাবে নির্ধারণ করা যাবে।</p><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="create_verify_key"><label>Key label</label><input name="label" placeholder="Telegram Bot / Website"><div class="grid3"><div><label>Wait for SMS (seconds · 0–60)</label><input type="number" name="wait_seconds" min="0" max="60" value="10"></div><div><label>Polling interval (ms · 250–5000)</label><input type="number" name="poll_interval_ms" min="250" max="5000" step="250" value="1000"></div><div><label>Requests / minute (10–300)</label><input type="number" name="rate_limit_per_min" min="10" max="300" value="120"></div></div><button class="secondary">Create verification key</button></form><div class="tablewrap" style="margin-top:12px"><table><thead><tr><th>Key Hint</th><th>Label</th><th>Status</th><th>Copy key</th><th>Wait · Poll · Rate/min</th><th>Action</th></tr></thead><tbody><?php foreach($verifyKeys as $hash=>$k):if(!is_array($k))continue;$copySecret=decrypt_admin_key($k);?><tr><td><?=h((string)($k['key_hint']??''))?></td><td><?=h((string)($k['label']??''))?></td><td><?=$badge(!empty($k['active'])?'ACTIVE':'REVOKED',!empty($k['active']))?></td><td><?php if($copySecret!==''):?><button type="button" class="secondary small" data-secret="<?=h($copySecret)?>" onclick="navigator.clipboard.writeText(this.dataset.secret).then(()=>this.textContent='Copied')">Copy key</button><?php else:?><span class="muted">Legacy key</span><?php endif;?></td><td><?php if(!empty($k['active'])):?><form method="post" class="inlineform"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="update_verify_key_timing"><input type="hidden" name="hash" value="<?=h((string)$hash)?>"><input aria-label="Wait seconds" title="Wait seconds" type="number" name="wait_seconds" min="0" max="60" value="<?=h((string)($k['wait_seconds']??10))?>" style="width:72px"><input aria-label="Polling milliseconds" title="Polling milliseconds" type="number" name="poll_interval_ms" min="250" max="5000" step="250" value="<?=h((string)($k['poll_interval_ms']??1000))?>" style="width:90px"><input aria-label="Requests per minute" title="Requests per minute" type="number" name="rate_limit_per_min" min="10" max="300" value="<?=h((string)($k['rate_limit_per_min']??120))?>" style="width:82px"><button class="small">Save</button></form><?php else:?>—<?php endif;?></td><td><?php if(!empty($k['active'])):?><form method="post" style="display:inline-block"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="revoke_verify_key"><input type="hidden" name="hash" value="<?=h((string)$hash)?>"><button class="danger small">Revoke</button></form><?php endif;?><form method="post" style="display:inline-block" onsubmit="return confirm('Permanently delete this Verification API Key? Integrations using it will stop working.')"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="delete_verify_key"><input type="hidden" name="hash" value="<?=h((string)$hash)?>"><button class="danger small">Delete</button></form></td></tr><?php endforeach;?></tbody></table></div></section></div>
      <section class="panel"><h2>Verification API example</h2><p>GET request supports `amount` and legacy `ammount`; POST + X-API-Key header is safer. Key query string public browser code-এ রাখবে না।</p><div class="keybox">GET /api/verify?apikey=PBV_KEY&amp;amount=505&amp;txnid=DKD7G02UOP&amp;method=bkash</div><div class="sectionnote">Transaction ID-only lookup: `GET /api/verify?apikey=PBV_KEY&amp;txnid=DKD7G02UOP` (only Transaction ID rule ON থাকলে amount/method/number input লাগবে না; matching complete transaction record response-এ আসবে)। `status` Boolean, `result` result label. প্রতি PBV key-এর নিজস্ব rolling requests/minute limit-ও এখানে set করা যায়.</div><p>Selected period-এর মোট Verify Request: <b><?=number_format($apiRequests)?></b> · Success: <b><?=number_format($apiSuccess)?></b> · Pending: <b><?=number_format($apiMetrics['result_pending']??0)?></b> · Failed: <b><?=number_format($apiMetrics['result_failed']??0)?></b></p></section>
    <?php elseif ($tab === 'data'): ?>
      <section class="panel"><div class="panelhead"><h2>Firebase Realtime Database data</h2><span class="badge good">Read only · Admin</span></div><p>এখানে selected Firebase node-এর বর্তমান data দেখা যাবে। Service Account key বা raw API key কখনো Firebase-এ সংরক্ষণ করা হয় না।</p><form method="get" class="filter"><input type="hidden" name="tab" value="data"><input type="hidden" name="month" value="<?=h($month)?>"><input type="hidden" name="period" value="<?=h($period)?>"><input type="hidden" name="year" value="<?=h((string)$reportYear)?>"><div class="wide"><label>Firebase path</label><select name="node"><?php foreach(['verification'=>'settings/verification','devices'=>'devices','app_keys'=>'settings/app_upload_keys','api_keys'=>'settings/verification_api_keys','monthly_report'=>'reports/monthly/' . $month . '/shards','monthly_api'=>'metrics/api_monthly/' . $month . '/shards'] as $k=>$label):?><option value="<?=h($k)?>" <?=$dataNode===$k?'selected':''?>><?=h($label)?></option><?php endforeach;?></select></div><div><label>&nbsp;</label><button>Load node</button></div></form><div class="keybox" style="white-space:pre;overflow:auto;max-height:560px;font-size:11px"><?=h(json_encode($firebaseDataView, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}')?></div></section>
    <?php elseif ($tab === 'devices'): ?>
      <section class="panel"><div class="panelhead"><h2>Connected Android installations</h2><span class="badge"><?=count($devices)?> total · <?=$devicesNeedAttention?> need attention</span></div><p>এক নজরে permission, heartbeat ও pending queue health। বর্তমানে মোট <?=$pendingQueueTotal?>টি payment SMS device queue-তে pending আছে। কোনো device key binding বা signer SHA-256 নেই; একই App Upload Key একাধিক device-এ ব্যবহার করা যায়।</p><div class="tablewrap"><table><thead><tr><th>Installation ID</th><th>Label</th><th>Model</th><th>Status</th><th>Last Login</th><th>Last Connect</th><th>Last Heartbeat</th><th>App Version</th><th>Android SDK</th><th>SMS</th><th>Notifications</th><th>Battery</th><th>Background</th><th>Network</th><th>Pending Queue</th><th>Control</th></tr></thead><tbody><?php foreach($devices as $id=>$d):if(!is_array($d))continue;?><tr><td><?=h(substr((string)$id,0,18))?>…</td><td><?=h((string)($d['label']??''))?></td><td><?=h((string)($d['model']??''))?></td><td><?=$badge((string)($d['connection_state']??'unknown'),!empty($d['active'])&&empty($d['blocked']))?></td><td><?=!empty($d['last_login_at'])?h(date('d/m/Y H:i',(int)$d['last_login_at'])):'-'?></td><td><?=!empty($d['last_connect_at'])?h(date('d/m/Y H:i',(int)$d['last_connect_at'])):'-'?></td><td><?=!empty($d['last_heartbeat_at'])?h(date('d/m/Y H:i',(int)$d['last_heartbeat_at'])):'-'?></td><td><?=h((string)($d['app_version']??'-'))?></td><td><?=!empty($d['android_sdk'])?h((string)$d['android_sdk']):'-'?></td><td><?=$badge(array_key_exists('permission_sms',$d)?(!empty($d['permission_sms'])?'GRANTED':'MISSING'):'UNKNOWN',array_key_exists('permission_sms',$d)&&!empty($d['permission_sms']))?></td><td><?=$badge(array_key_exists('permission_notifications',$d)?(!empty($d['permission_notifications'])?'ALLOWED':'BLOCKED'):'UNKNOWN',array_key_exists('permission_notifications',$d)&&!empty($d['permission_notifications']))?></td><td><?=$badge(array_key_exists('permission_battery_exempt',$d)?(!empty($d['permission_battery_exempt'])?'EXEMPT':'OPTIMIZED'):'UNKNOWN',array_key_exists('permission_battery_exempt',$d)&&!empty($d['permission_battery_exempt']))?></td><td><?=$badge(array_key_exists('background_restricted',$d)?(!empty($d['background_restricted'])?'RESTRICTED':'OK'):'UNKNOWN',array_key_exists('background_restricted',$d)&&empty($d['background_restricted']))?></td><td><?=$badge(array_key_exists('network_connected',$d)?(!empty($d['network_connected'])?'ONLINE':'OFFLINE'):'UNKNOWN',array_key_exists('network_connected',$d)&&!empty($d['network_connected']))?></td><td><?=number_format((int)($d['pending_queue_count']??0))?></td><td><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="device_toggle"><input type="hidden" name="device_id" value="<?=h((string)$id)?>"><input type="hidden" name="blocked" value="<?=empty($d['blocked'])?'1':'0'?>"><button class="<?=empty($d['blocked'])?'danger':'small'?> small"><?=empty($d['blocked'])?'Block':'Unblock'?></button></form></td></tr><?php endforeach;?></tbody></table></div></section>
    <?php elseif ($tab === 'settings'): ?>
      <div class="grid2"><section class="panel"><h2>Verification rules</h2><p>Enabled rules are ANDed together. Txn ID is used for indexed lookup even if its compare switch is turned off.</p><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="save_verification"><div class="checkgrid"><?php foreach(['verify_number'=>'Sender number','verify_amount'=>'Amount','verify_txn_id'=>'Transaction ID','verify_method'=>'Payment method'] as $field=>$label):?><div class="checkitem"><label><input type="checkbox" name="<?=$field?>" <?=!empty($verification[$field])?'checked':''?>><?=h($label)?></label></div><?php endforeach;?></div><label>Wait for SMS sync (seconds, 0–60)</label><input type="number" name="wait_seconds" min="0" max="60" value="<?=h((string)$verification['wait_seconds'])?>"><label>Firebase polling interval (ms, 250–5000)</label><input type="number" name="poll_interval_ms" min="250" max="5000" step="250" value="<?=h((string)$verification['poll_interval_ms'])?>"><button style="margin-top:13px">Save verification settings</button></form></section><section class="panel"><h2>System information</h2><p>Database: Firebase Realtime Database only</p><p>Backend: Single PHP index.php</p><p>Timezone: Asia/Dhaka</p><p>Application upload keys: shared across multiple devices</p><p>Signer SHA-256: disabled</p><p>Request-by-request logs: disabled; only daily/monthly aggregate API counters are stored for reporting.</p><p>Verification API limit: per-key rolling window, 10–300 requests per minute; default 120. Admin can change each PBV key limit.</p><p>Payment records are kept by unique Method + Txn ID. Used records cannot be verified again.</p></section></div>
    <?php endif; ?>
    <footer class="muted" style="padding:16px 3px;font-size:10px">PAYMENT BRIDGE · SINGLE PHP ADMIN + API · FIREBASE RTDB · NO SQL</footer></main></div></body></html><?php
}

$route = current_route();
if (strpos($route, 'api/') === 0 || $route === 'healthz') handle_api();
admin_page();
