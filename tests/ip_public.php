<?php
// Unit check for sv_ip_is_public / sv_public_source_error. Run it on the
// production PHP version too (8.2's filter_var calls ::ffff:127.0.0.1 public):
//   docker run --rm -v "$PWD":/sv caddy-setup-php-fpm php /sv/tests/ip_public.php
declare(strict_types=1);
require __DIR__ . '/../admin/includes/helpers.php';
$public = ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '::ffff:1.1.1.1', '64:ff9b::101:101'];
$private = ['127.0.0.1', '10.0.0.1', '172.18.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '198.18.0.1', '192.0.0.8', '::1', '::', '::ffff:127.0.0.1',
    '::ffff:169.254.169.254', '::ffff:10.0.0.1', '::127.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::',
    '2002:a00:1::1', '2001:0:1::1', 'fd00::1', 'fe80::1', 'ff02::1', 'garbage'];
$urls = ['http://[::ffff:127.0.0.1]:2019/', 'http://[::ffff:7f00:1]/', 'http://127.0.0.1/', 'http://[::1]/', 'ftp://1.1.1.1/'];
$bad = 0;
foreach ($public as $ip) if (!sv_ip_is_public($ip)) { echo "FAIL: $ip should be public\n"; $bad++; }
foreach ($private as $ip) if (sv_ip_is_public($ip)) { echo "FAIL: $ip should not be public\n"; $bad++; }
foreach ($urls as $u) if (sv_public_source_error($u) === null) { echo "FAIL: $u should be rejected\n"; $bad++; }
if (sv_public_source_error('https://1.1.1.1/x.m3u8') !== null) { echo "FAIL: public URL rejected\n"; $bad++; }
echo $bad ? "IP CHECKS FAILED\n" : "ALL IP CHECKS PASSED (PHP " . PHP_VERSION . ")\n";
exit($bad ? 1 : 0);
