<?php
header("Content-Type: text/plain");
echo "PHP Version: " . PHP_VERSION . "\n";
echo "SAPI: " . php_sapi_name() . "\n";
echo "upload_progress.enabled: " . ini_get("session.upload_progress.enabled") . "\n";
echo "use_strict_mode: " . ini_get("session.use_strict_mode") . "\n";
echo "Status: OK\n";
