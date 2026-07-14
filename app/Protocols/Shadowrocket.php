<?php

namespace App\Protocols;

use App\Utils\Helper;

class Shadowrocket
{
    public $flag = 'shadowrocket';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $user = $this->user;

        $uri = '';
        //display remaining traffic and expire date
        $upload = round($user['u'] / (1024*1024*1024), 2);
        $download = round($user['d'] / (1024*1024*1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        $expiredDate = date('Y-m-d', $user['expired_at']);
        $uri .= "STATUS=🚀↑:{$upload}GB,↓:{$download}GB,TOT:{$totalTraffic}GB💡Expires:{$expiredDate}\r\n";

        foreach ($this->servers as $server) {
            // -------- [shadow-tls / SS插件  修改] 原版只分流 vmess;这里加了 shadowsocks 分支 --------
            $realType = ($server['type'] === 'v2node' && isset($server['protocol'])) ? $server['protocol'] : $server['type'];
            if ($realType === 'vmess') {
                $uri .= self::buildVmess($user['uuid'], $server);
            } elseif ($realType === 'shadowsocks') {
                $uri .= self::buildShadowsocks($user['uuid'], $server);   // ← 新增分支(走下面新增的方法)
            } else {
                $uri .= Helper::buildUri($this->user['uuid'], $server);
            }
            // -------- 修改结束 --------
        }
        return base64_encode($uri);
    }

    // ==================== [shadow-tls / SS插件  新增开始] ====================
    // 以下 buildShadowsocks 方法是本功能新增,原版没有。
    // Shadowrocket does NOT understand SIP003 `plugin=shadow-tls` in an ss:// URI.
    // It uses its own scheme: ss://b64(cipher:pw)@host:port?shadow-tls=b64(JSON),
    // where the JSON is {"version","password","host","port","address"}.
    // Non-shadow-tls SS falls back to the generic ss:// builder.
    public static function buildShadowsocks($uuid, $server)
    {
        $p = Helper::ssPlugin($server);
        if ($p === null || $p['plugin'] !== 'shadow-tls') {
            return Helper::buildShadowsocksUri($uuid, $server);
        }
        $cipher = $server['cipher'];
        if (strpos($cipher, '2022-blake3') !== false) {
            $length = $cipher === '2022-blake3-aes-128-gcm' ? 16 : 32;
            $serverKey = Helper::getServerKey($server['created_at'], $length);
            $userKey = Helper::uuidToBase64($uuid, $length);
            $password = "{$serverKey}:{$userKey}";
        } else {
            $password = $uuid;
        }
        $userinfo = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{$cipher}:{$password}"));
        $opts = $p['opts'];
        // Explicit, distinct address (node) and host (SNI) — matches the tested
        // ShadowTLS-Manager format. address is the shadow-tls connect target (the
        // node); host is the cleartext TLS SNI. Keeping them separate stops
        // Shadowrocket from using the SNI as the connect address.
        $stlsConfig = json_encode([
            'version'  => (string)($opts['version'] ?? '3'),
            'password' => (string)($opts['password'] ?? ''),
            'host'     => (string)($opts['host'] ?? ''),
            'port'     => (string)$server['port'],
            'address'  => (string)$server['host'],
        ], JSON_UNESCAPED_SLASHES);
        $stlsB64 = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($stlsConfig));
        $name = rawurlencode($server['name']);
        $host = Helper::formatHost($server['host']);
        return "ss://{$userinfo}@{$host}:{$server['port']}?shadow-tls={$stlsB64}#{$name}\r\n";
    }
    // ==================== [shadow-tls / SS插件  新增结束] ====================

    public static function buildVmess($uuid, $server)
    {
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if ($server['tls']) {
            $config['tls'] = 1;
            $tlsSettings = $server['tls_settings'] ?? ($server['tlsSettings'] ?? []);
            $config['allowInsecure'] = (int)($tlsSettings['allow_insecure'] ?? $tlsSettings['allowInsecure'] ?? 0);
            $config['peer'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
        }
        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                $config['obfs'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                $config['path'] = $tcpSettings['header']['request']['path'][0];
            if (isset($tcpSettings['header']['request']['headers']['Host'][0]))
                $config['obfsParam'] = $tcpSettings['header']['request']['headers']['Host'][0];
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            $wsSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                $config['path'] = $wsSettings['path'];
            if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                $config['obfsParam'] = $wsSettings['headers']['Host'];
            if (isset($wsSettings['security']))
                $config['method'] = $wsSettings['security'];
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            $grpcSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                $config['path'] = $grpcSettings['serviceName'];
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
            } else {
                $config['host'] = $server['host'];
            }
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

}
