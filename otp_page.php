<?php
/* ============================================================
   Read OTP — standalone single-page file
   API: https://mailgen.shop (public, no key needed)
   শুধু এই একটা ফাইল host করলেই চলবে।
   ============================================================ */

define('MAILGEN_BASE', 'https://mailgen.shop');
define('RATE_PER_MIN', 30);   // per-IP per minute

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
session_start();
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

/* ─── tiny helpers ─── */
function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function icon(string $n): string {
    static $map = [
        'mail'   => '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-10 6L2 7"/>',
        'send'   => '<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
        'shield' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'copy'   => '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
        'key'    => '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
        'inbox'  => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    ];
    return '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">' . ($map[$n] ?? '') . '</svg>';
}

function otp_svg(string $p): string {
    return '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">' . $p . '</svg>';
}

/* ─── TOTP (local, no API) ─── */
function base32_decode_raw(string $s): ?string {
    $s = strtoupper(preg_replace('/[\s=\-]+/', '', $s));
    if (!preg_match('/^[A-Z2-7]+$/', $s)) return null;
    $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
    $bits = '';
    foreach (str_split($s) as $c) $bits .= str_pad(decbin($map[$c]), 5, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split($bits, 8) as $b) if (strlen($b) === 8) $out .= chr(bindec($b));
    return $out === '' ? null : $out;
}
function totp_code(string $secret): ?string {
    // accept otpauth:// URL
    if (preg_match('/secret=([^&\s]+)/i', $secret, $m)) $secret = urldecode($m[1]);
    $key = base32_decode_raw($secret);
    if ($key === null) return null;
    $h = hash_hmac('sha1', pack('J', intdiv(time(), 30)), $key, true);
    $o = ord($h[19]) & 15;
    $n = ((ord($h[$o])   & 0x7f) << 24)
       |  (ord($h[$o+1]) << 16)
       |  (ord($h[$o+2]) << 8)
       |   ord($h[$o+3]);
    return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
}
function totp_remaining(): int { return 30 - (time() % 30); }

/* ─── rate limiter (tmp-file, no DB needed) ─── */
function rate_ok(): bool {
    $ip  = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'x')[0]);
    $f   = sys_get_temp_dir() . '/otp_rl_' . md5($ip);
    $now = time();
    $a   = is_file($f)
         ? array_filter(array_map('intval', explode(',', (string)@file_get_contents($f))), fn($t) => $t > $now - 60)
         : [];
    if (count($a) >= RATE_PER_MIN) return false;
    $a[] = $now;
    @file_put_contents($f, implode(',', $a), LOCK_EX);
    return true;
}

/* ─── MailGen API call ─── */
function mg_call(string $endpoint, array $payload): array {
    $url = rtrim(MAILGEN_BASE, '/') . '/' . ltrim($endpoint, '/');
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 45,
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);
    $raw  = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false || $raw === '')
        return ['_http' => 0, 'error' => 'Connection failed: ' . $err];

    $j = json_decode((string)$raw, true);
    if (!is_array($j))
        return ['_http' => $code, 'error' => 'Bad response (HTTP ' . $code . ')'];

    $j['_http'] = $code;
    return $j;
}

/* ─── extract code from a single message array ─── */
function otp_pick_code(array $m): ?string {
    // prefer the API's own code field (it's already extracted for us)
    if (!empty($m['code']) && is_string($m['code']) && preg_match('/^\d{4,8}$/', trim($m['code'])))
        return trim($m['code']);

    // fallback: parse subject + preview/message text
    $body = '';
    foreach (['message', 'text', 'body', 'preview', 'snippet'] as $k) {
        if (!empty($m[$k]) && is_string($m[$k])) { $body = $m[$k]; break; }
    }
    $texts = [(string)($m['subject'] ?? ''), $body];
    foreach ($texts as $t) {
        if (trim($t) === '') continue;
        if (preg_match('/\b(?:code|otp|pin|passcode|token)\b[^0-9\n]{0,30}?\b(\d{4,8})\b/i', $t, $x)) return $x[1];
        if (preg_match('/\b(\d{4,8})\b(?=\s+(?:is|as)\s+your)/i', $t, $x)) return $x[1];
        if (preg_match('/\b(\d{3})[-\s](\d{3})\b/', $t, $x)) return $x[1] . $x[2];
        if (preg_match('/\b(\d{6})\b/', $t, $x)) return $x[1];
        if (preg_match_all('/\b(\d{4,8})\b/', $t, $all))
            foreach ($all[1] as $n)
                if (!(strlen($n) === 4 && (int)$n >= 1900 && (int)$n <= 2100)) return $n;
    }
    return null;
}

/* ─── get body text for "Full mail" viewer ─── */
function otp_mail_body(array $m): array {
    foreach (['html', 'htmlBody', 'message', 'text', 'body', 'preview', 'snippet'] as $k) {
        $v = $m[$k] ?? null;
        if (!is_string($v) || trim($v) === '') continue;
        $v = mb_substr($v, 0, 400000);
        return [$v, (bool)preg_match('/<\/?(html|body|div|p|table|br|span|a|img|td|h[1-6])\b/i', $v)];
    }
    return ['', false];
}

/* ─── run one OTP request ─── */
function otp_run(string $tab, string $raw): array {
    $r = ['err' => '', 'apiErr' => '', 'messages' => [], 'found' => null, 'totp' => null, 'empty' => false];

    // grab first non-empty line
    $first = '';
    foreach (preg_split('/\r\n|\r|\n/', $raw) as $l) {
        $l = trim($l);
        if ($l !== '') { $first = $l; break; }
    }
    if ($first === '') { $r['err'] = 'Please enter your details first.'; return $r; }
    if (strlen($first) > 2000) { $r['err'] = 'Input is too long.'; return $r; }

    /* ── TOTP (no API call) ── */
    if ($tab === 'totp') {
        $code = totp_code($first);
        if ($code === null) $r['err'] = 'Invalid 2FA key. Use a Base32 key such as JBSWY3DPEHPK3PXP.';
        else $r['totp'] = ['code' => $code, 'rem' => totp_remaining()];
        return $r;
    }

    /* ── Edu mail ── */
    if ($tab === 'email') {
        $email = strtolower($first);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $r['err'] = 'Invalid email address.'; return $r; }
        // POST /api/edu-mail   { "email": "..." }
        $res = mg_call('/api/edu-mail', ['email' => $email]);
        return otp_parse_response($r, $res);
    }

    /* ── Hotmail / Outlook (OAuth2) ── */
    if ($tab === 'hotmail') {
        $parts = array_map('trim', explode('|', $first));
        if (count($parts) < 4 || !filter_var($parts[0], FILTER_VALIDATE_EMAIL)) {
            $r['err'] = 'Invalid format. Use: email|refresh_token|client_id|client_secret';
            return $r;
        }
        // POST /api/get-inbox   { "data": "...", "mode": "oauth" }
        $res = mg_call('/api/get-inbox', ['data' => $first, 'mode' => 'oauth']);
        return otp_parse_response($r, $res);
    }

    /* ── Roundcube ── */
    if ($tab === 'roundcube') {
        $parts = array_map('trim', explode('|', $first));
        if (count($parts) < 2 || !filter_var($parts[0], FILTER_VALIDATE_EMAIL)) {
            $r['err'] = 'Invalid format. Use: user@wmhotmail.com|password';
            return $r;
        }
        // POST /api/get-inbox   { "data": "...", "mode": "roundcube" }
        $res = mg_call('/api/get-inbox', ['data' => $first, 'mode' => 'roundcube']);
        return otp_parse_response($r, $res);
    }

    $r['err'] = 'Unknown tab.';
    return $r;
}

function otp_parse_response(array $r, array $res): array {
    // rate limit
    if (($res['_http'] ?? 0) === 429) {
        $wait = $res['retry_after'] ?? '?';
        $r['apiErr'] = 'Rate limit exceeded. Try again in ' . $wait . ' seconds.';
        return $r;
    }
    // messages array
    if (!empty($res['messages']) && is_array($res['messages'])) {
        $r['messages'] = $res['messages'];
        foreach ($res['messages'] as $m) {
            $c = otp_pick_code($m);
            if ($c) { $r['found'] = ['code' => $c]; break; }
        }
        return $r;
    }
    // explicit error
    if (!empty($res['error']) && $res['error'] !== null) {
        $r['apiErr'] = is_string($res['error']) ? $res['error'] : json_encode($res['error']);
        return $r;
    }
    if (!empty($res['status']) && is_string($res['status']) && strtolower($res['status']) !== 'success') {
        $r['apiErr'] = $res['status'];
        return $r;
    }
    $r['empty'] = true;
    return $r;
}

/* ─── HTML for result area (used by AJAX) ─── */
function otp_out_html(array $r): string {
    ob_start();
    if ($r['err'])    echo '<div class="otp-err">' . e($r['err']) . '</div>';
    if ($r['apiErr']) echo '<div class="otp-err"><b>API:</b> ' . e($r['apiErr']) . '</div>';

    if ($r['totp']):
        $c = $r['totp']['code'];
        $pretty = substr($c, 0, 3) . ' ' . substr($c, 3); ?>
        <div class="otp-result" data-totp data-rem="<?= (int)$r['totp']['rem'] ?>">
          <div class="lb"><?= icon('shield') ?> 2FA code</div>
          <div class="code"><?= e($pretty) ?></div>
          <div class="tm"><span class="bar"><i></i></span><b class="sec"><?= (int)$r['totp']['rem'] ?>s</b></div>
          <button type="button" class="cp" data-code="<?= e($c) ?>"><?= icon('copy') ?><span>Copy code</span></button>
        </div>
    <?php endif;

    if ($r['messages']):
        $list = array_slice($r['messages'], 0, 15); ?>
        <div class="otp-found"><?= count($list) ?> email(s) found</div>
        <?php foreach ($list as $i => $m):
            if (!is_array($m)) continue;
            $code = otp_pick_code($m); ?>
          <div class="mc">
            <?php if ($code): ?>
            <div class="mc-top">
              <div class="mc-code"><?= e($code) ?></div>
              <button type="button" class="mc-cp" data-code="<?= e($code) ?>" aria-label="Copy" title="Copy code"><?= icon('copy') ?></button>
            </div>
            <?php endif; ?>
            <div class="mc-sub"><?= e($m['subject'] ?? '(no subject)') ?></div>
            <div class="mc-meta"><?= e((string)($m['from'] ?? 'Unknown')) ?><?php if (!empty($m['date'])): ?> &bull; <?= e($m['date']) ?><?php endif; ?></div>
            <button type="button" class="mc-full" data-i="<?= $i ?>">Full mail</button>
          </div>
        <?php endforeach;
    elseif ($r['empty']): ?>
        <div class="otp-box otp-none"><div class="em">📭</div><b>No messages found</b><p>The inbox is empty or no verification code was received.</p></div>
    <?php endif;
    return ob_get_clean();
}

/* ═══ AJAX handler ═══ */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        echo json_encode(['html' => '<div class="otp-err">Session expired. Reload the page.</div>', 'mails' => []]);
        exit;
    }
    session_write_close();

    if (!rate_ok()) {
        http_response_code(429);
        echo json_encode(['html' => '<div class="otp-err">Too many requests. Wait a minute and try again.</div>', 'mails' => []]);
        exit;
    }

    $valid_tabs = ['hotmail', 'email', 'totp', 'roundcube'];
    $t = in_array($_POST['tab'] ?? '', $valid_tabs, true) ? $_POST['tab'] : 'hotmail';
    $r = otp_run($t, (string)($_POST['data'] ?? ''));

    $mails = [];
    foreach (array_slice($r['messages'], 0, 15) as $m) {
        if (!is_array($m)) continue;
        [$body, $isHtml] = otp_mail_body($m);
        $mails[] = [
            'subject' => (string)($m['subject'] ?? '(no subject)'),
            'from'    => (string)($m['from']    ?? ''),
            'date'    => (string)($m['date']    ?? ''),
            'body'    => $body,
            'html'    => $isHtml,
        ];
    }
    echo json_encode(
        ['html' => otp_out_html($r), 'mails' => $mails],
        JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}

/* ═══ Page config ═══ */
$TABS = ['hotmail', 'email', 'roundcube', 'totp'];
$tab  = in_array($_GET['tab'] ?? '', $TABS, true) ? $_GET['tab'] : 'hotmail';

$panes = [
    'hotmail' => [
        'icon'  => 'mail', 'title' => 'Hotmail & Outlook', 'tab' => 'Hotmail',
        'btn'   => 'Get Code', 'busy' => 'Checking inbox…', 'mailbox' => true, 'multi' => true,
        'hint'  => 'Paste your Outlook / Hotmail / Live account credentials to read the latest code.',
        'ph'    => 'user@outlook.com|refresh_token|client_id|client_secret',
        'fmt'   => '<code>email | refresh_token | client_id | client_secret</code>',
        'tips'  => [
            'Supported: <code>@hotmail.com</code> <code>@outlook.com</code> <code>@live.com</code>',
            'Uses OAuth2 mode via MailGen API.',
            'Your credentials are sent only to mailgen.shop and are never stored.',
        ],
    ],
    'email' => [
        'icon'  => 'inbox', 'title' => 'Edu / Fake Mail', 'tab' => 'Edu Mail',
        'btn'   => 'Get Code', 'busy' => 'Checking inbox…', 'mailbox' => false, 'multi' => false,
        'hint'  => 'Enter a Gmail Edu or EmailFake address — no password required.',
        'ph'    => 'user@emailfake.com',
        'fmt'   => '<code>email</code> (emailfake / Gmail Edu)',
        'tips'  => [
            'Just enter the address — no password needed.',
            'Example: <code>user@emailfake.com</code>',
            'Only works with Gmail Edu / EmailFake accounts.',
        ],
    ],
    'roundcube' => [
        'icon'  => 'send', 'title' => 'Roundcube (wmhotmail)', 'tab' => 'Roundcube',
        'btn'   => 'Get Code', 'busy' => 'Checking inbox…', 'mailbox' => false, 'multi' => false,
        'hint'  => 'Enter wmhotmail.com credentials to read via Roundcube webmail.',
        'ph'    => 'user@wmhotmail.com|password',
        'fmt'   => '<code>email | password</code> (wmhotmail.com accounts)',
        'tips'  => [
            'Only works with <code>@wmhotmail.com</code> accounts.',
            'Uses Roundcube webmail mode.',
            'Your credentials are sent only to mailgen.shop.',
        ],
    ],
    'totp' => [
        'icon'  => 'shield', 'title' => '2FA Key', 'tab' => '2FA Key',
        'btn'   => 'Get 2FA Code', 'busy' => 'Generating…', 'mailbox' => false, 'multi' => false,
        'hint'  => 'Paste your Base32 secret key to generate the current 6-digit code.',
        'ph'    => 'JBSWY3DPEHPK3PXP',
        'fmt'   => '<code>BASE32_SECRET</code> or full <code>otpauth://</code> URL',
        'tips'  => [
            'The code refreshes every 30 seconds automatically.',
            'Calculated locally — your key is never sent to any server.',
            'Spaces and dashes in the key are stripped automatically.',
        ],
    ],
];
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Read OTP</title>
<style>
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:#f1f4f9;color:#1e293b;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px 12px 40px}
h2,h3,h4,p,ul{margin:0}
code{background:#fff;padding:1px 6px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;color:#4338ca;border:1px solid #e0e7ff;overflow-wrap:anywhere;display:inline}
svg.i{width:1em;height:1em;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;display:inline-block;vertical-align:-.1em}

/* ── layout ── */
.otp-wrap{max-width:460px;margin:0 auto}

/* hero */
.otp-hero{display:flex;align-items:center;gap:12px;padding:14px 16px;margin-bottom:12px;border-radius:16px;color:#fff;position:relative;overflow:hidden;background:linear-gradient(135deg,#4338ca,#6d28d9);box-shadow:0 12px 26px -16px rgba(67,56,202,.7)}
.otp-hero::after{content:"";position:absolute;right:-34px;top:-52px;width:130px;height:130px;border-radius:50%;background:rgba(255,255,255,.09)}
.otp-hero .hb{position:relative;z-index:1;width:36px;height:36px;border-radius:11px;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.28);display:flex;align-items:center;justify-content:center;flex:none}
.otp-hero .hb svg.i{width:18px;height:18px}
.otp-hero div:last-child{position:relative;z-index:1;min-width:0}
.otp-hero h2{font-size:1rem;line-height:1.25;color:#fff}
.otp-hero p{margin-top:1px;font-size:.78rem;line-height:1.4;color:rgba(255,255,255,.82)}

/* tabs — 4 columns */
.otp-tabs{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;padding:4px;margin-bottom:12px;background:#eef1f6;border:1px solid #e2e8f0;border-radius:13px}
.otp-tabs button{display:flex;align-items:center;justify-content:center;gap:5px;min-width:0;padding:8px 4px;border:0;border-radius:10px;background:transparent;color:#64748b;font:inherit;font-size:.73rem;font-weight:600;line-height:1.2;cursor:pointer;transition:background .15s,color .15s,box-shadow .15s;-webkit-tap-highlight-color:transparent}
.otp-tabs button svg.i{width:13px;height:13px;flex:none}
.otp-tabs button span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.otp-tabs button:hover:not(.on){color:#334155;background:rgba(255,255,255,.6)}
.otp-tabs button.on{background:#fff;color:#4338ca;box-shadow:0 1px 3px rgba(15,23,42,.12),0 0 0 1px rgba(79,70,229,.1)}
@media(max-width:420px){.otp-tabs button svg.i{display:none}.otp-tabs button{font-size:.7rem;padding:8px 2px}}

/* card */
.otp-card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:16px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 10px 24px -16px rgba(30,27,75,.25);margin-bottom:12px}
.otp-pane[hidden]{display:none}
.otp-card h3{margin:0 0 3px;font-size:.95rem;display:flex;align-items:center;gap:8px}
.ic{width:24px;height:24px;border-radius:8px;flex:none;background:#eef2ff;border:1px solid #e0e7ff;display:inline-flex;align-items:center;justify-content:center}
.ic svg.i{width:13px;height:13px;color:#4f46e5}
.otp-card .hint{font-size:.8rem;color:#64748b;margin:0 0 11px;line-height:1.45}

/* input */
.otp-input{display:block;width:100%;padding:10px 12px;border:1.5px solid #d5dbe5;border-radius:11px;background:#f8fafc;color:#1e293b;font:inherit;font-size:.84rem;line-height:1.45;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;transition:border .15s,box-shadow .15s,background .15s}
textarea.otp-input{min-height:72px;resize:vertical}
.otp-input:focus{outline:0;border-color:#4f46e5;background:#fff;box-shadow:0 0 0 3px rgba(79,70,229,.12)}
.otp-input::placeholder{color:#a0aabb}

/* format hint */
.otp-format{display:flex;align-items:flex-start;gap:8px;margin-top:8px;padding:8px 11px;background:#f6f8fb;border:1px solid #e6ebf2;border-radius:10px;font-size:.76rem;color:#556275;line-height:1.5}
.otp-format svg.i{width:14px;height:14px;color:#4f46e5;flex:none;margin-top:1px}
.otp-format[hidden]{display:none}

/* email chip */
.otp-mail{display:flex;align-items:center;gap:8px;margin-top:8px;padding:6px 6px 6px 11px;background:#f0fdf4;border:1px solid #bbf0cc;border-radius:10px;font-size:.78rem}
.otp-mail[hidden]{display:none}
.otp-mail .lbl{flex:none;font-size:.66rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#15803d}
.otp-mail .mv{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;color:#14532d;overflow-wrap:anywhere}
.mcp{flex:none;width:32px;height:32px;border:1px solid #bbf0cc;border-radius:9px;background:#fff;color:#15803d;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,transform .1s}
.mcp svg.i{width:16px;height:16px}
.mcp:active{transform:scale(.93)}
.mcp.done{background:#16a34a;border-color:#16a34a;color:#fff}

/* toolbar */
.otp-tools{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:0 0 6px}
.otp-tools .tl{font-size:.74rem;font-weight:600;color:#556275}
.otp-tools .tb{display:flex;gap:6px}
.tbtn{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border:1px solid #dfe5f7;background:#f5f6ff;color:#4338ca;border-radius:8px;font:inherit;font-size:.74rem;font-weight:600;cursor:pointer;transition:background .15s,transform .1s}
.tbtn svg.i{width:13px;height:13px}
.tbtn:hover{background:#eceffd}
.tbtn:active{transform:scale(.96)}
.tbtn[data-act=clean]{color:#b45309;background:#fff7ed;border-color:#fde3c4}
.tbtn[data-act=clean]:hover{background:#ffedd5}

/* submit button */
.otp-go{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;margin-top:11px;padding:12px 14px;border:0;border-radius:11px;color:#fff;font:inherit;font-weight:700;font-size:.9rem;background:linear-gradient(135deg,#4f46e5,#6d28d9);box-shadow:0 8px 18px -10px rgba(79,70,229,.8),inset 0 1px 0 rgba(255,255,255,.2);cursor:pointer;transition:transform .12s,filter .15s}
.otp-go:hover{filter:brightness(1.06)}
.otp-go:active{transform:scale(.985)}
.otp-go svg.i{width:17px;height:17px}
.otp-go:disabled{opacity:.8;cursor:wait}
.otp-go.load svg.i{display:none}
.otp-go.load::before{content:"";width:15px;height:15px;border-radius:50%;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;animation:otpSp .7s linear infinite}
@keyframes otpSp{to{transform:rotate(360deg)}}
@keyframes otpUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* info box */
.otp-info{margin-top:12px;padding:10px 12px;border-radius:11px;background:#f5f6ff;border:1px dashed #cfd6f7;font-size:.78rem;color:#4338ca}
.otp-info h4{margin:0 0 5px;font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.otp-info h4 svg.i{width:12px;height:12px}
.otp-info ul{padding:0;list-style:none}
.otp-info li{position:relative;padding:2px 0 2px 14px;color:#556275;line-height:1.5}
.otp-info li::before{content:"";position:absolute;left:3px;top:.72em;width:4px;height:4px;border-radius:50%;background:#6366f1}

/* ── results ── */
.otp-out>*{animation:otpUp .3s both}
.otp-err{background:#fef2f2;color:#b91c1c;padding:10px 12px;border-radius:11px;margin-bottom:12px;font-size:.84rem;border:1px solid #fecaca}

/* TOTP result */
.otp-result{position:relative;overflow:hidden;text-align:center;padding:18px 16px 16px;margin-bottom:12px;border-radius:16px;background:linear-gradient(135deg,#ecfdf3,#f7fefa);border:1px solid #a7e8be}
.otp-result::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,#16a34a,#4ade80,#16a34a)}
.otp-result .lb{display:inline-flex;align-items:center;gap:6px;font-size:.68rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#15803d}
.otp-result .lb svg.i{width:13px;height:13px}
.otp-result .code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:2.2rem;font-weight:800;letter-spacing:.18em;line-height:1.15;margin:6px 0 10px;color:#15803d;word-break:break-all}
.otp-result .tm{display:flex;align-items:center;gap:10px;max-width:240px;margin:0 auto 12px}
.otp-result .bar{flex:1;height:5px;border-radius:99px;background:#cdeed8;overflow:hidden}
.otp-result .bar i{display:block;height:100%;width:100%;border-radius:99px;background:#16a34a;transition:width .3s linear,background .3s}
.otp-result .bar.low i{background:#f59e0b}
.otp-result .sec{font-size:.78rem;font-weight:700;color:#15803d;min-width:28px;text-align:right}
.otp-result .cp{display:inline-flex;align-items:center;gap:7px;padding:9px 20px;border:0;border-radius:10px;background:#16a34a;color:#fff;font:inherit;font-weight:600;font-size:.84rem;box-shadow:0 8px 16px -8px rgba(22,163,74,.8);cursor:pointer;transition:transform .12s}
.otp-result .cp:active{transform:scale(.97)}
.otp-result .cp svg.i{width:15px;height:15px}
.otp-result .cp.done{background:#15803d}

/* mail list */
.otp-found{text-align:center;color:#16a34a;font-weight:600;font-size:.82rem;margin:2px 0 10px}
.otp-none{text-align:center;padding:24px 16px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;margin-bottom:12px}
.otp-none .em{font-size:1.8rem;margin-bottom:4px}
.otp-none b{font-size:.9rem}
.otp-none p{color:#64748b;font-size:.8rem;margin:5px 0 0}
.mc{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:12px;margin-bottom:10px;box-shadow:0 1px 2px rgba(15,23,42,.04),0 10px 22px -16px rgba(30,27,75,.25)}
.mc-top{display:flex;gap:8px;margin-bottom:10px}
.mc-code{flex:1;min-width:0;display:flex;align-items:center;justify-content:center;padding:9px 8px;border:1.5px dashed #6366f1;border-radius:12px;background:#eef2ff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.55rem;font-weight:800;letter-spacing:.2em;color:#4338ca;word-break:break-all;text-indent:.2em}
.mc-cp{flex:none;width:46px;border:1px solid #e2e8f0;border-radius:12px;background:#fff;color:#4f46e5;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s,transform .1s}
.mc-cp svg.i{width:18px;height:18px}
.mc-cp:active{transform:scale(.95)}
.mc-cp.done{background:#16a34a;border-color:#16a34a;color:#fff}
.mc-sub{font-weight:700;font-size:.88rem;line-height:1.35;color:#1e293b;overflow-wrap:anywhere}
.mc-meta{margin:3px 0 10px;color:#7b8798;font-size:.74rem;overflow-wrap:anywhere}
.mc-full{display:block;width:100%;padding:9px;border:0;border-radius:10px;background:linear-gradient(135deg,#4f46e5,#6d28d9);color:#fff;font:inherit;font-weight:600;font-size:.84rem;cursor:pointer;transition:filter .15s,transform .1s}
.mc-full:hover{filter:brightness(1.07)}
.mc-full:active{transform:scale(.985)}

/* full mail dialog */
.fm{position:fixed;inset:0;z-index:3500;display:none;align-items:center;justify-content:center;padding:14px}
.fm.open{display:flex}
.fm-bd{position:absolute;inset:0;background:rgba(15,23,42,.55)}
.fm-sh{position:relative;display:flex;flex-direction:column;width:100%;max-width:560px;height:min(86vh,720px);background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 24px 60px rgba(15,23,42,.35)}
.fm-h{display:flex;gap:10px;align-items:flex-start;padding:13px 14px;border-bottom:1px solid #eef1f6}
.fm-t{flex:1;min-width:0}
.fm-t b{display:block;font-size:.92rem;line-height:1.35;color:#1e293b;overflow-wrap:anywhere}
.fm-t small{display:block;margin-top:2px;color:#7b8798;font-size:.74rem;overflow-wrap:anywhere}
.fm-x{flex:none;width:30px;height:30px;border:0;border-radius:50%;background:#f1f5f9;color:#475569;font-size:20px;line-height:1;cursor:pointer}
.fm-b{flex:1;min-height:0;overflow:auto;background:#fff}
.fm-b iframe{display:block;width:100%;height:100%;border:0;background:#fff}
.fm-b pre{margin:0;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:.84rem;line-height:1.6;color:#334155}
</style>
</head>
<body>

<div class="otp-wrap" id="otpWrap" data-csrf="<?= e($_SESSION['csrf']) ?>">

  <!-- hero -->
  <div class="otp-hero">
    <div class="hb"><?= icon('key') ?></div>
    <div><h2>Read OTP</h2><p>mailgen.shop &mdash; no key required.</p></div>
  </div>

  <!-- tabs -->
  <div class="otp-tabs" role="tablist" aria-label="OTP method">
    <?php foreach ($panes as $k => $p): ?>
    <button type="button" role="tab" data-tab="<?= $k ?>"
            class="<?= $tab === $k ? 'on' : '' ?>"
            aria-selected="<?= $tab === $k ? 'true' : 'false' ?>">
      <?= icon($p['icon']) ?><span><?= e($p['tab']) ?></span>
    </button>
    <?php endforeach; ?>
  </div>

  <!-- panes -->
  <?php foreach ($panes as $k => $p): ?>
  <div class="otp-pane" data-pane="<?= $k ?>"<?= $tab === $k ? '' : ' hidden' ?>>
    <div class="otp-card">
      <h3><span class="ic"><?= icon($p['icon']) ?></span><?= e($p['title']) ?></h3>
      <p class="hint"><?= e($p['hint']) ?></p>

      <form class="otp-form" data-tab="<?= $k ?>" autocomplete="off" novalidate>
        <!-- toolbar -->
        <div class="otp-tools">
          <span class="tl">
            <?php if ($p['multi']): ?>Account data
            <?php elseif ($k === 'totp'): ?>2FA secret key
            <?php elseif ($k === 'roundcube'): ?>Account data
            <?php else: ?>Email address<?php endif; ?>
          </span>
          <span class="tb">
            <button type="button" class="tbtn" data-act="paste">
              <?= otp_svg('<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>') ?>
              <span>Paste</span>
            </button>
            <button type="button" class="tbtn" data-act="clean">
              <?= otp_svg('<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>') ?>
              <span>Clear</span>
            </button>
          </span>
        </div>

        <!-- input -->
        <?php if ($p['multi']): ?>
          <textarea class="otp-input" name="data" rows="3" spellcheck="false" placeholder="<?= e($p['ph']) ?>"></textarea>
        <?php else: ?>
          <input class="otp-input" type="text" name="data" spellcheck="false" autocapitalize="off" placeholder="<?= e($p['ph']) ?>">
        <?php endif; ?>

        <!-- format hint / email chip -->
        <div class="otp-format"><?= icon('shield') ?><span>Format: <?= $p['fmt'] ?></span></div>
        <?php if ($p['mailbox']): ?>
        <div class="otp-mail" hidden>
          <span class="lbl">Email</span><b class="mv"></b>
          <button type="button" class="mcp" data-code="" aria-label="Copy email"><?= icon('copy') ?></button>
        </div>
        <?php endif; ?>

        <button type="submit" class="otp-go" data-label="<?= e($p['btn']) ?>" data-busy="<?= e($p['busy']) ?>">
          <?= icon('send') ?><span><?= e($p['btn']) ?></span>
        </button>
      </form>

      <div class="otp-info">
        <h4><?= icon('shield') ?> Instructions</h4>
        <ul><?php foreach ($p['tips'] as $t): ?><li><?= $t ?></li><?php endforeach; ?></ul>
      </div>
    </div>
    <div class="otp-out" aria-live="polite"></div>
  </div>
  <?php endforeach; ?>

</div><!-- /otp-wrap -->

<script>
(function(){
  var wrap = document.getElementById('otpWrap');
  if (!wrap) return;
  var csrf = wrap.dataset.csrf, timers = {}, busy = {}, mails = {};

  function qs(s, r){ return (r||document).querySelector(s); }
  function qsa(s, r){ return [].slice.call((r||document).querySelectorAll(s)); }

  /* ── tabs ── */
  function setTab(t){
    qsa('.otp-tabs button').forEach(function(b){
      var on = b.dataset.tab === t;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    qsa('.otp-pane').forEach(function(p){ p.hidden = p.dataset.pane !== t; });
    try{ history.replaceState(null, '', '?tab=' + t); } catch(e){}
  }
  qsa('.otp-tabs button').forEach(function(b){
    b.addEventListener('click', function(){ setTab(b.dataset.tab); });
  });

  /* ── TOTP countdown ── */
  function startTotp(tab, out){
    clearInterval(timers[tab]);
    var el = qs('[data-totp]', out); if (!el) return;
    var end  = Date.now() + (parseInt(el.dataset.rem, 10) || 30) * 1000,
        bar  = qs('.bar', el),
        fill = qs('.bar i', el),
        sec  = qs('.sec', el),
        pane = out.parentNode;
    function tick(){
      if (pane.hidden || !document.body.contains(el)){ clearInterval(timers[tab]); return; }
      var left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      sec.textContent = left + 's';
      fill.style.width = (left / 30 * 100) + '%';
      bar.classList.toggle('low', left <= 5);
      if (left <= 0){ clearInterval(timers[tab]); run(tab, true); }
    }
    tick(); timers[tab] = setInterval(tick, 250);
  }

  /* ── email chip ── */
  var EM = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}/;
  function syncMail(f){
    var box = qs('.otp-mail', f); if (!box) return;
    var line = (f.elements.data.value.split(/\r?\n/)[0] || '').split('|')[0];
    var m = line.match(EM);
    box.hidden = !m;
    qs('.otp-format', f).hidden = !!m;
    if (m){ qs('.mv', box).textContent = m[0]; qs('.mcp', box).dataset.code = m[0]; }
  }

  /* ── clean pasted text ── */
  function clean(v){
    return String(v)
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .replace(/\r/g, '')
      .split('\n')
      .map(function(l){ return l.split('|').map(function(x){ return x.trim(); }).join('|').trim(); })
      .filter(Boolean)
      .join('\n');
  }

  /* ── per-form listeners ── */
  qsa('.otp-form').forEach(function(f){
    var inp = f.elements.data;
    inp.addEventListener('input',  function(){ syncMail(f); });
    inp.addEventListener('paste',  function(){ setTimeout(function(){ inp.value = clean(inp.value); syncMail(f); }, 0); });

    f.addEventListener('click', function(e){
      var b = e.target.closest('.tbtn'); if (!b) return;
      var tab = f.dataset.tab, s = qs('span', b), orig = s.textContent;
      if (b.dataset.act === 'clean'){
        inp.value = ''; syncMail(f); clearInterval(timers[tab]); delete mails[tab];
        qs('.otp-out', f.closest('.otp-pane')).innerHTML = ''; inp.focus(); return;
      }
      // paste from clipboard
      function got(t){ inp.value = clean(t); syncMail(f); inp.focus(); s.textContent = 'Pasted!'; setTimeout(function(){ s.textContent = orig; }, 1300); }
      function hint(){ inp.focus(); s.textContent = 'Long-press to paste'; setTimeout(function(){ s.textContent = orig; }, 2200); }
      if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext)
        navigator.clipboard.readText().then(function(t){ t ? got(t) : hint(); }, hint);
      else hint();
    });
  });

  /* ── fetch OTP ── */
  function run(tab, silent){
    var pane = qs('.otp-pane[data-pane="' + tab + '"]'),
        f    = qs('form', pane),
        inp  = f.elements.data,
        btn  = qs('.otp-go', f),
        lab  = qs('span', btn),
        out  = qs('.otp-out', pane);

    if (!silent) inp.value = clean(inp.value);
    if (!inp.value.trim()){ inp.focus(); return; }
    if (busy[tab]) return;
    busy[tab] = true;
    if (!silent){
      btn.disabled = true;
      btn.classList.add('load');
      lab.textContent = btn.dataset.busy || 'Checking\u2026';
    }

    fetch(location.pathname, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
      body: new URLSearchParams({ ajax: '1', csrf: csrf, tab: tab, data: inp.value })
    })
    .then(function(r){ return r.json().catch(function(){ throw new Error(r.status); }); })
    .then(function(j){
      out.innerHTML = j.html;
      mails[tab] = j.mails || [];
      startTotp(tab, out);
      if (!silent){
        var el = qs('.mc-top, .otp-result, .otp-err', out) || out;
        setTimeout(function(){ try{ el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch(e){} }, 60);
      }
    })
    .catch(function(){
      if (!silent) out.innerHTML = '<div class="otp-err">Request failed. Check your connection or reload the page.</div>';
    })
    .then(function(){
      busy[tab] = false;
      btn.disabled = false;
      btn.classList.remove('load');
      lab.textContent = btn.dataset.label;
    });
  }

  qsa('.otp-form').forEach(function(f){
    f.addEventListener('submit', function(e){ e.preventDefault(); run(f.dataset.tab, false); });
    if (f.elements.data.tagName === 'TEXTAREA')
      f.elements.data.addEventListener('keydown', function(e){
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)){ e.preventDefault(); run(f.dataset.tab, false); }
      });
  });

  /* ── copy buttons ── */
  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.cp, .mc-cp, .mcp'); if (!b || !b.dataset.code) return;
    var t = b.dataset.code, s = qs('span', b), orig = s ? s.textContent : '';
    function done(){ if (s) s.textContent = 'Copied!'; b.classList.add('done'); setTimeout(function(){ if (s) s.textContent = orig; b.classList.remove('done'); }, 1600); }
    function fb(){ var a = document.createElement('textarea'); a.value = t; a.style.cssText = 'position:fixed;left:-9999px'; document.body.appendChild(a); a.select(); try{ document.execCommand('copy'); } catch(x){} document.body.removeChild(a); done(); }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done, fb); else fb();
  });

  /* ── full mail dialog ── */
  var FM = null;
  function buildFM(){
    FM = document.createElement('div');
    FM.className = 'fm';
    FM.setAttribute('aria-hidden', 'true');
    FM.innerHTML =
      '<div class="fm-bd" data-x></div>' +
      '<div class="fm-sh" role="dialog" aria-modal="true">' +
        '<div class="fm-h"><div class="fm-t"><b></b><small></small></div>' +
        '<button type="button" class="fm-x" data-x aria-label="Close">&times;</button></div>' +
        '<div class="fm-b"></div>' +
      '</div>';
    document.body.appendChild(FM);
    FM.addEventListener('click', function(e){ if (e.target.closest('[data-x]')) closeFM(); });
    document.addEventListener('keydown', function(e){ if (e.key === 'Escape' && FM.classList.contains('open')) closeFM(); });
  }
  function closeFM(){
    FM.classList.remove('open');
    FM.setAttribute('aria-hidden', 'true');
    qs('.fm-b', FM).innerHTML = '';
    document.documentElement.style.overflow = '';
  }
  function openFM(m){
    if (!FM) buildFM();
    qs('.fm-t b', FM).textContent = m.subject || '(no subject)';
    qs('.fm-t small', FM).textContent = [m.from, m.date].filter(Boolean).join(' \u2022 ');
    var box = qs('.fm-b', FM);
    box.innerHTML = '';
    if (!m.body){
      var pre = document.createElement('pre'); pre.textContent = 'Full message body is not available for this email.'; box.appendChild(pre);
    } else if (m.html){
      var fr = document.createElement('iframe');
      fr.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
      fr.setAttribute('referrerpolicy', 'no-referrer');
      fr.srcdoc = '<base target="_blank"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{margin:12px;font-family:system-ui,sans-serif;font-size:14px;line-height:1.55;color:#1e293b;word-break:break-word}img{max-width:100%;height:auto}</style>' + m.body;
      box.appendChild(fr);
    } else {
      var pr = document.createElement('pre'); pr.textContent = m.body; box.appendChild(pr);
    }
    FM.classList.add('open');
    FM.setAttribute('aria-hidden', 'false');
    document.documentElement.style.overflow = 'hidden';
  }

  wrap.addEventListener('click', function(e){
    var b = e.target.closest('.mc-full'); if (!b) return;
    var pane = b.closest('.otp-pane');
    var m = (mails[pane.dataset.pane] || [])[parseInt(b.dataset.i, 10)];
    if (m) openFM(m);
  });

})();
</script>
</body>
</html>
