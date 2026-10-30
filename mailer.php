<?php
/* مسار — إرسال البريد من استضافة هوستنجر بطلبات موقّعة من خادم مسار (Ed25519)، بلا كلمات مرور */
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
const MASAR_PUB = 'WvZpHbxBLknGaR6hqPv/RMM+T6Ly9SvtPhBRIzWnLkI=';
const MASAR_FROM = 'masar@masarbonyan.online';
function out($code, $a) { http_response_code($code); echo json_encode($a, JSON_UNESCAPED_UNICODE); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, ['ok' => false]);
if (!function_exists('sodium_crypto_sign_verify_detached')) out(500, ['ok' => false, 'error' => 'sodium']);
$in = json_decode(file_get_contents('php://input'), true);
if (!is_array($in) || !isset($in['p'], $in['s'])) out(400, ['ok' => false, 'error' => 'bad']);
$sig = base64_decode($in['s'], true); $pub = base64_decode(MASAR_PUB, true);
if ($sig === false || strlen($sig) !== 64 || $pub === false || strlen($pub) !== 32) out(400, ['ok' => false, 'error' => 'sig']);
if (!sodium_crypto_sign_verify_detached($sig, $in['p'], $pub)) out(403, ['ok' => false, 'error' => 'verify']);
$m = json_decode($in['p'], true);
if (!is_array($m) || abs(time() - intval($m['ts'] ?? 0)) > 300) out(403, ['ok' => false, 'error' => 'expired']);
// منع إعادة استخدام الطلب نفسه
$seen = sys_get_temp_dir() . '/masar_mail_' . substr(hash('sha256', $in['s']), 0, 32);
if (file_exists($seen)) out(409, ['ok' => false, 'error' => 'replay']);
@touch($seen);
$to = array_values(array_filter((array)($m['to'] ?? []), function ($a) { return filter_var($a, FILTER_VALIDATE_EMAIL); }));
if (!$to || count($to) > 60) out(400, ['ok' => false, 'error' => 'to']);
$headers = str_replace(["\r\n.", "\0"], ["\r\n..", ''], (string)($m['headers'] ?? ''));
$subject = preg_replace('/[\r\n]+/', ' ', (string)($m['subject'] ?? ''));
$body = (string)($m['body'] ?? '');
$sent = 0;
foreach ($to as $rcpt) { if (mail($rcpt, $subject, $body, $headers, '-f' . MASAR_FROM)) $sent++; }
out($sent ? 200 : 500, ['ok' => $sent > 0, 'sent' => $sent]);
